package core

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	F "github.com/lzpls/enimul/internal/fmt"
	"github.com/lzpls/enimul/internal/log"
)

type tunnelSession = struct {
	logger                 log.Logger
	p                      *Policy
	cliConn, dstConn       net.Conn
	oldTarget              string
	target                 *dial.Dst
	originHost, originPort string
	port                   string
	fromSNIProxy           bool
}

func (c *Core) handleTunnel(ts *tunnelSession) {
	var (
		err       error
		closeHere = true
	)
	closeBoth := func() {
		ts.cliConn.Close()
		if ts.dstConn != nil {
			ts.dstConn.Close()
		}
	}
	defer func() {
		if closeHere {
			closeBoth()
		}
	}()

	if ts.p.Mode == ModeRaw {
		if ts.dstConn == nil {
			ts.dstConn, err = dial.DialTCPTimeoutMulti(ts.target, ts.port, ts.p.ConnectTimeout)
			if err != nil {
				ts.logger.Error("Connection to ", ts.oldTarget, " failed: ", err)
				return
			}
		}
	} else {
		br := bufio.NewReader(ts.cliConn)
		peekBytes, err := br.Peek(10)
		if err != nil {
			if len(peekBytes) == 0 && errors.Is(err, io.EOF) {
				ts.logger.Error("Empty tunnel")
			} else {
				ts.logger.Error("Read first packet: ", err)
			}
			return
		}

		if peekBytes[0] == tlsRecordTypeHandshake {
			if peekBytes[1] == tlsMajorVersion {
				payloadLen := 5 + int(binary.BigEndian.Uint16(peekBytes[3:5]))
				if !c.handleTLS(ts, payloadLen, br) {
					return
				}
			}
		} else if bytesHasPrefix(peekBytes,
			"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
			"OPTIONS ", "TRACE ", "PATCH ",
		) {
			if req, err := http.ReadRequest(br); err != nil {
				ts.logger.Error("Trying parsing HTTP: ", err)
			} else if !handleHTTP(ts, req) {
				return
			}
		} else {
			ts.logger.Info("Unknown protocol")
		}
		if !drainBuffered(ts.logger, br, ts.dstConn) {
			return
		}
	}

	closeHere = false
	forward(ts.logger, ts.cliConn, ts.dstConn, ts.originHost)
}

func drainBuffered(logger log.Logger, br *bufio.Reader, dst net.Conn) bool {
	if n := br.Buffered(); n > 0 {
		buf, err := br.Peek(n)
		if err != nil {
			logger.Error("Read buffered data: ", err)
			return false
		}
		if _, err := dst.Write(buf); err != nil {
			logger.Error("Send drained buffered data: ", err)
			return false
		}
	}
	return true
}

func forward(logger log.Logger, srcConn, dstConn net.Conn, dstAddr string) {
	logger.Info("Start forwarding")
	srcTCPConn, dstTCPConn := srcConn.(*net.TCPConn), dstConn.(*net.TCPConn)
	closeBoth := func() {
		dstTCPConn.Close()
		srcTCPConn.Close()
	}
	var done atomic.Bool
	go func() {
		if _, err := io.Copy(dstTCPConn, srcTCPConn); err != nil {
			closeBoth()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Error("Forward ", srcTCPConn.RemoteAddr(), "->", dstAddr, ": ", err)
			return
		}
		logger.Debug("Forward ", srcTCPConn.RemoteAddr(), "->", dstAddr, " finished")
		if err := dstTCPConn.CloseWrite(); err != nil || done.Swap(true) {
			closeBoth()
		}
	}()
	go func() {
		if _, err := io.Copy(srcTCPConn, dstTCPConn); err != nil {
			closeBoth()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Error("Forward ", dstAddr, "->", srcTCPConn.RemoteAddr(), ": ", err)
			return
		}
		logger.Debug("Forward ", dstAddr, "->", srcTCPConn.RemoteAddr(), " finished")
		if err := srcTCPConn.CloseWrite(); err != nil || done.Swap(true) {
			closeBoth()
		}
	}()
}

func handleHTTP(ts *tunnelSession, req *http.Request) (ok bool) {
	defer req.Body.Close()

	host := req.Host
	if host == "" {
		host = req.URL.Host
		if host == "" {
			host = ts.originHost
		}
	}
	ts.logger.Info("host=", host, " method=", req.Method, " url=", req.URL)

	var err error

	if ts.p.HttpStatus != 0 && ts.p.HttpStatus != unsetInt {
		statusLine := strconv.Itoa(ts.p.HttpStatus) + " " + http.StatusText(ts.p.HttpStatus)
		resp := &http.Response{
			Status:        statusLine,
			StatusCode:    ts.p.HttpStatus,
			Proto:         req.Proto,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			ContentLength: 0,
			Close:         true,
		}
		if ts.p.HttpStatus == 301 || ts.p.HttpStatus == 302 {
			resp.Header.Set("Location", "https://"+host+req.URL.RequestURI())
		}
		if err = resp.Write(ts.cliConn); err != nil {
			ts.logger.Error("Send ", ts.p.HttpStatus, ": ", err)
		} else {
			ts.logger.Info("Sent ", statusLine)
		}
		return
	}
	if ts.dstConn == nil {
		ts.dstConn, err = dial.DialTCPTimeoutMulti(ts.target, ts.port, ts.p.ConnectTimeout)
		if err != nil {
			ts.logger.Error("Connection to ", ts.oldTarget, " failed: ", err)
			resp := &http.Response{
				Status:        status502,
				StatusCode:    502,
				Proto:         req.Proto,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        make(http.Header),
				ContentLength: 0,
				Close:         true,
			}
			if err = resp.Write(ts.cliConn); err != nil {
				ts.logger.Debug("Failed to send 502: ", err)
			}
			return
		}
	}
	if err := req.Write(ts.dstConn); err != nil {
		ts.logger.Error("Forward HTTP request: ", err)
		return
	}
	return true
}

func (c *Core) handleTLS(ts *tunnelSession, recordLen int, br *bufio.Reader) (ok bool) {
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(br, record); err != nil {
		ts.logger.Error("Read first record: ", err)
		return
	}
	prtVer, sniStart, sniLen, isTLS13, hasECH, err := parseClientHello(record)
	if err != nil {
		ts.logger.Error("Parse record: ", err)
		return
	}
	if ts.p.Mode == ModeTLSAlert {
		sendTLSAlert(ts.logger, ts.cliConn, prtVer, tlsAlertAccessDenied, tlsAlertLevelFatal)
		return
	}
	if !checkTLS13Only(ts.logger, isTLS13, ts.p, ts.cliConn, prtVer) {
		return
	}

	var mode Mode
	if sniStart <= 0 {
		const msg = "SNI not found"
		if ts.fromSNIProxy {
			ts.logger.Error(msg)
			return
		}
		ts.logger.Info(msg)
		mode = ModeDirect
	} else if hasECH {
		msg := []any{"ECH detected ", "(SNI=", record[sniStart : sniStart+sniLen], "), ignored"}
		if ts.fromSNIProxy {
			ts.logger.Error(msg...)
			return
		}
		ts.logger.Info(msg...)
		mode = ModeDirect
	} else if sniStr := string(record[sniStart : sniStart+sniLen]); ts.fromSNIProxy || ts.originHost != sniStr {
		if ts.fromSNIProxy {
			ts.logger.Info("SNI: ", sniStr)
			ts.originHost = sniStr
		} else {
			ts.logger.Info("Mismatched SNI: ", sniStr)
		}
		switch ts.p.SniffOverrideMode {
		case SniffOverrideRouteOnly:
			if sniPolicy, exists := c.domainMatcher.Find(sniStr); exists {
				switch sniPolicy.Mode {
				case ModeBlock:
					ts.logger.Info("Connection blocked: ", sniStr)
					return
				case ModeTLSAlert:
					ts.logger.Info("Connection blocked (TLS alert): ", sniStr)
					sendTLSAlert(ts.logger, ts.cliConn, prtVer, tlsAlertAccessDenied, tlsAlertLevelFatal)
					return
				}
				if !checkTLS13Only(ts.logger, isTLS13, sniPolicy, ts.cliConn, prtVer) {
					return
				}
				ts.p = mergePolicies(sniPolicy, ts.p)
				ts.logger.Info("SNI policy: ", ts.p)
			}
		case SniffOverrideAlways, SniffOverridePolicyExists:
			newDst, sniPolicy, failed, blocked, policyNotExists := c.genPolicy(
				ts.logger, sniStr, false, !ts.fromSNIProxy && ts.p.SniffOverrideMode == SniffOverridePolicyExists)
			switch {
			case failed:
				if ts.fromSNIProxy {
					ts.logger.Error("Failed to generate SNI Policy")
					return
				}
				ts.logger.Warn("Failed to generate SNI policy; falling back to origin")
			case policyNotExists:
				ts.logger.Info("SNI policy not found; falling back to origin")
			default:
				if blocked {
					ts.logger.Info("Connection blocked: ", sniStr)
					return
				}
				if sniPolicy.Mode == ModeTLSAlert {
					ts.logger.Info("Connection blocked (TLS alert): ", sniStr)
					sendTLSAlert(ts.logger, ts.cliConn, prtVer, tlsAlertAccessDenied, tlsAlertLevelFatal)
					return
				}
				if !checkTLS13Only(ts.logger, isTLS13, sniPolicy, ts.cliConn, prtVer) {
					return
				}
				ts.logger.Info("SNI policy: ", sniPolicy)
				port := ts.originPort
				if sniPolicy.Port != 0 && sniPolicy.Port != unsetInt {
					port = F.Int(sniPolicy.Port)
				}
				newConn, err := dial.DialTCPTimeoutMulti(newDst, port, sniPolicy.ConnectTimeout)
				if err == nil {
					if ts.dstConn != nil {
						ts.dstConn.Close()
					}
					ts.dstConn, ts.p, ts.target, ts.port = newConn, sniPolicy, newDst, port
					if !ts.fromSNIProxy {
						ts.logger.Info("Target has been changed to ", sniStr)
					}
				} else if ts.fromSNIProxy {
					ts.logger.Error("Connection to ", net.JoinHostPort(sniStr, port), " failed:", err)
					return
				} else {
					ts.logger.Error("Connection to ", net.JoinHostPort(sniStr, port), " failed:", err, "; falling back to origin")
				}
			}
		}
	}

	if ts.dstConn == nil {
		ts.dstConn, err = dial.DialTCPTimeoutMulti(ts.target, ts.port, ts.p.ConnectTimeout)
		if err != nil {
			ts.logger.Error("Connection to ", ts.oldTarget, " failed: ", err)
			return
		}
	}
	if mode == ModeUnset {
		mode = ts.p.Mode
	}

	switch mode {
	case ModeDirect, ModeRaw:
		if _, err = ts.dstConn.Write(record); err != nil {
			ts.logger.Error("Send ClientHello directly: ", err)
			return
		}
		ts.logger.Info("Sent ClientHello directly")
	case ModeTLSRF:
		err = sendRecords(ts.dstConn, record, sniStart, sniLen,
			ts.p.NumRecords, ts.p.NumSegments, ts.p.MinorVer,
			ts.p.OOB.IsTrue(), ts.p.OOBEx.IsTrue(),
			ts.p.WaitForAck.IsTrue(), ts.p.SendInterval)
		if err != nil {
			ts.logger.Error("TLS fragment: ", err)
			return
		}
		ts.logger.Info("Sent ClientHello in fragments")
	case ModeTTLD:
		ttl, err := c.getFakeTTL(ts.logger, ts.p, ts.dstConn.RemoteAddr().(*net.TCPAddr).AddrPort())
		if err != nil {
			ts.logger.Error("Get fake TTL: ", err)
			return
		}
		if err = desyncSend(
			ts.dstConn, record,
			sniStart, sniLen, ttl, ts.p.FakeSleep,
		); err != nil {
			ts.logger.Error("TTL desync: ", err)
			return
		}
		ts.logger.Info("Sent ClientHello with fake packet")
	}
	return true
}

func checkTLS13Only(logger log.Logger, isTLS13 bool, p *Policy, conn net.Conn, prtVer []byte) (ok bool) {
	if !isTLS13 && p.TLS13Only.IsTrue() {
		logger.Info("Connection blocked: key_share missing from ClientHello")
		sendTLSAlert(logger, conn, prtVer, tlsAlertProtocolVersion, tlsAlertLevelFatal)
		return
	}
	return true
}

const (
	tlsAlertLevelFatal      byte = 2
	tlsAlertAccessDenied    byte = 70
	tlsAlertProtocolVersion byte = 49
)

func sendTLSAlert(logger log.Logger, conn net.Conn, prtVer []byte, desc byte, level byte) {
	_, err := conn.Write([]byte{0x15, prtVer[0], prtVer[1], 0x0, 0x2, level, desc})
	if err != nil {
		logger.Error("Send TLS alert: ", err)
	}
}

const (
	tlsRecordTypeHandshake      = 0x16
	tlsMajorVersion             = 0x3
	tlsRecordHeaderLen          = 5
	tlsHandshakeHeaderLen       = 4
	tlsHandshakeTypeClientHello = 0x1
	tlsExtTypeSNI               = 0x0000
	tlsExtTypeSupportedVersions = 0x002b
	tlsExtTypeECH               = 0x00fe
)

func parseClientHello(data []byte) (prtVer []byte, sniStart int, sniLen int, isTLS13, hasECH bool, err error) {
	if data[0] != tlsRecordTypeHandshake {
		return nil, -1, 0, false, false, E.New("not a TLS handshake record")
	}

	if data[1] != tlsMajorVersion {
		return nil, -1, 0, false, false, E.New("not a standard TLS record")
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < tlsRecordHeaderLen+recordLen {
		return nil, -1, 0, false, false, E.New("record length exceeds data size")
	}
	offset := tlsRecordHeaderLen

	if recordLen < tlsHandshakeHeaderLen {
		return nil, -1, 0, false, false, E.New("handshake message too short")
	}
	if data[offset] != tlsHandshakeTypeClientHello {
		return nil, -1, 0, false, false, fmt.Errorf("not a ClientHello handshake (type=%d)", data[offset])
	}
	handshakeLen := int(uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
	if handshakeLen+tlsHandshakeHeaderLen > recordLen {
		return nil, -1, 0, false, false, E.New("handshake length exceeds record length")
	}
	offset += tlsHandshakeHeaderLen

	if handshakeLen < 2+32+1 {
		return nil, -1, 0, false, false, E.New("ClientHello too short for mandatory fields")
	}
	prtVer = data[offset : offset+2]
	offset += 2 + 32
	if offset >= len(data) {
		return prtVer, -1, 0, false, false, E.New("unexpected end after Random")
	}
	sessionIDLen := int(data[offset])
	offset++
	if offset+sessionIDLen > len(data) {
		return prtVer, -1, 0, false, false, E.New("session_id length exceeds data")
	}
	offset += sessionIDLen

	if offset+2 > len(data) {
		return prtVer, -1, 0, false, false, E.New("cannot read cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+csLen > len(data) {
		return prtVer, -1, 0, false, false, E.New("cipher_suites exceed data")
	}
	offset += csLen

	if offset >= len(data) {
		return prtVer, -1, 0, false, false, E.New("cannot read compression_methods length")
	}
	compMethodsLen := int(data[offset])
	offset++
	if offset+compMethodsLen > len(data) {
		return prtVer, -1, 0, false, false, E.New("compression_methods exceed data")
	}
	offset += compMethodsLen

	// Extensions
	if offset+2 > len(data) {
		return prtVer, -1, 0, false, false, nil
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+extTotalLen > len(data) {
		return prtVer, -1, 0, false, false, E.New("extensions length exceeds data")
	}
	extensionsEnd := offset + extTotalLen

	sniStart = -1

	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		extDataStart := offset + 4
		extDataEnd := extDataStart + extLen
		if extDataEnd > extensionsEnd {
			return prtVer, sniStart, sniLen, isTLS13, hasECH, E.New("extension length exceeds extensions block")
		}

		switch extType {
		case tlsExtTypeSupportedVersions:
			isTLS13 = true
		case tlsExtTypeECH:
			hasECH = true
		case tlsExtTypeSNI:
			if sniStart != -1 {
				return prtVer, sniStart, sniLen, isTLS13, hasECH, E.New("duplicate SNI extension")
			}
			if extLen < 2 {
				return prtVer, sniStart, sniLen, isTLS13, hasECH, E.New("malformed SNI extension (too short for list length)")
			}
			listLen := int(binary.BigEndian.Uint16(data[extDataStart : extDataStart+2]))
			if listLen+2 != extLen {
				return prtVer, sniStart, sniLen, isTLS13, hasECH, E.New("SNI list length field mismatch")
			}
			cursor := extDataStart + 2
			if cursor+3 > extDataEnd {
				return prtVer, sniStart, sniLen, isTLS13, hasECH, E.New("SNI entry too short")
			}
			nameType := data[cursor]
			if nameType != 0 {
				return prtVer, sniStart, sniLen, isTLS13, hasECH, E.New("unsupported SNI name type")
			}
			nameLen := int(binary.BigEndian.Uint16(data[cursor+1 : cursor+3]))
			nameStart := cursor + 3
			nameEnd := nameStart + nameLen
			if nameEnd > extDataEnd {
				return prtVer, sniStart, sniLen, isTLS13, hasECH, E.New("SNI name length exceeds extension")
			}
			sniStart = nameStart
			sniLen = nameLen
		}
		offset = extDataEnd
	}
	return prtVer, sniStart, sniLen, isTLS13, hasECH, nil
}

func bytesHasPrefix(b []byte, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if string(b[:len(prefix)]) == prefix {
			return true
		}
	}
	return false
}

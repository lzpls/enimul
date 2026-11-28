package core

import (
	"encoding/binary"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/lzpls/enimul/internal/dial"
	F "github.com/lzpls/enimul/internal/fmt"
	"github.com/lzpls/enimul/internal/log"
)

const (
	socks5ReplyNoAuth               = "\x05\x00"
	socks5ReplyUsernamePasswordAuth = "\x05\x02"
	socks5ReplyAuthSuccess          = "\x01\x00"
	socks5ReplyAuthFailure          = "\x01\x01"
	socks5ReplySuccess              = "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
	socks5ReplyServerFailure        = "\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"
	socks5ReplyConnNotAllowed       = "\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00"
	socks5ReplyCmdNotSupported      = "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"
	socks5ReplyAtypNotSupported     = "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00"
)

func (s *Server) serveSOCKS5(listenAddr string) {
	logger := s.logFactory.NewLogger("S[00000]")
	ln, err := listenTCP(listenAddr)
	if err != nil {
		logger.Error("Failed to start SOCKS5 server: ", err)
		return
	}
	defer ln.Close()
	logger.Info("SOCKS5 proxy server started at ", ln.Addr())

	var connID uint32
	var tempDelay time.Duration
	for {
		conn, err := ln.AcceptTCP()
		if err == nil {
			connID += 1
			if connID > maxConnID {
				connID = 1
			}
			go s.socks5Handler(conn, connID)
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Temporary() {
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			tempDelay = max(1*time.Second, tempDelay)
			logger.Warn("Accept failed: ", err, "; retrying in ", tempDelay)
			time.Sleep(tempDelay)
			continue
		}
		logger.Error("Accept failed (fatal): ", err)
		return
	}
}

func readN(conn *net.TCPConn, buf []byte) ([]byte, error) {
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func sendReply(logger log.Logger, conn *net.TCPConn, reply string) bool {
	if _, err := conn.Write([]byte(reply)); err != nil {
		logger.Error("Send SOCKS5 reply: ", err)
		return false
	}
	return true
}

var socks5BufferPool = sync.Pool{New: func() any { return new([256]byte) }}

func (s *Server) socks5Handler(cliConn *net.TCPConn, id uint32) {
	var dstConn *net.TCPConn
	closeConns := deferred(func() {
		if dstConn != nil {
			dstConn.Close()
		}
		cliConn.SetLinger(0)
		cliConn.Close()
	})
	defer closeConns.do()

	logger := s.logFactory.NewLogger(F.ConnIDToHex5("S", id))
	logger.Info("Connection from ", cliConn.RemoteAddr())

	var headerBuf [2]byte
	header, err := readN(cliConn, headerBuf[:])
	if err != nil {
		logger.Error("Read method selection: ", err)
		return
	}
	if header[0] != 0x5 {
		logger.Error("Expected socks version 5, but got ", F.Byte(header[0]))
		return
	}

	buf := socks5BufferPool.Get().(*[256]byte)
	putBuffer := deferred(func() { socks5BufferPool.Put(buf) })
	defer putBuffer.do()

	methods, err := readN(cliConn, buf[:header[1]])
	if err != nil {
		logger.Error("Read methods: ", err)
		return
	}

	if s.InboundAuth == nil {
		if !slices.Contains(methods, 0x0) {
			logger.Error("`no auth` method not found")
			return
		}
		if _, err = cliConn.Write([]byte(socks5ReplyNoAuth)); err != nil {
			logger.Error("Send auth method: ", err)
			return
		}
	} else if !slices.Contains(methods, 0x2) {
		logger.Error("Authentication failed: username/password auth method not found")
		return
	} else if _, err := cliConn.Write([]byte(socks5ReplyUsernamePasswordAuth)); err != nil {
		logger.Error("Authentication failed: send auth method: ", err)
		return
	} else if authHeader, err := readN(cliConn, buf[:2]); err != nil {
		logger.Error("Authentication failed: read username/password auth header: ", err)
		return
	} else if authHeader[0] != 0x1 || authHeader[1] == 0 {
		logger.Error("Authentication failed: invalid username/password auth header")
		cliConn.Write([]byte(socks5ReplyAuthFailure))
		return
	} else if usernameBytes, err := readN(cliConn, buf[:authHeader[1]]); err != nil {
		logger.Error("Authentication failed: read username: ", err)
		return
	} else {
		username := string(usernameBytes)
		passwordLen, err := readN(cliConn, buf[:1])
		if err != nil {
			logger.Error("Authentication failed: read password length: ", err)
			return
		}
		if passwordLen[0] == 0 {
			logger.Error("Authentication failed: empty password")
			cliConn.Write([]byte(socks5ReplyAuthFailure))
			return
		}
		passwordBytes, err := readN(cliConn, buf[:passwordLen[0]])
		if err != nil {
			logger.Error("Authentication failed: read password: ", err)
			return
		}
		if !s.InboundAuth.check(username, string(passwordBytes)) {
			logger.Error("Authentication failed: invalid username or password")
			cliConn.Write([]byte(socks5ReplyAuthFailure))
			return
		}
		if _, err = cliConn.Write([]byte(socks5ReplyAuthSuccess)); err != nil {
			logger.Error("Send auth success: ", err)
			return
		}
	}

	header, err = readN(cliConn, buf[:4])
	if err != nil {
		logger.Error("Read request header: ", err)
		return
	}
	if header[0] != 0x5 {
		logger.Error("Expected socks version 5, but got ", F.Byte(header[0]))
		return
	}
	if header[1] != 0x1 {
		logger.Error("Expected cmd CONNECT, but got ", F.Byte(header[1]))
		sendReply(logger, cliConn, socks5ReplyCmdNotSupported)
		return
	}

	var (
		originHost string
		dstHost    *dial.Dst
		policy     *Policy
		isIP       bool
	)
	switch header[3] {
	case 0x1: // IPv4 address
		ipBytes, err := readN(cliConn, buf[:4])
		if err != nil {
			logger.Error("Read IPv4 address: ", err)
			return
		}
		originHost = net.IP(ipBytes).String()
		isIP = true
	case 0x4: // IPv6 address
		ipBytes, err := readN(cliConn, buf[:16])
		if err != nil {
			logger.Error("Read IPv6 address: ", err)
			return
		}
		originHost = net.IP(ipBytes).String()
		isIP = true
	case 0x3: // Domain name
		lenByte, err := readN(cliConn, buf[:1])
		if err != nil {
			logger.Error("Read domain length: ", err)
			return
		}
		if lenByte[0] == 0 || lenByte[0] > 253 {
			logger.Error("Invalid domain length: ", lenByte[0])
			return
		}
		domainBytes, err := readN(cliConn, buf[:lenByte[0]])
		if err != nil {
			logger.Error("Read domain address: ", err)
			return
		}
		originHost = string(domainBytes)
	default:
		logger.Error("Invalid address type: ", F.Byte(header[3]))
		sendReply(logger, cliConn, socks5ReplyAtypNotSupported)
		return
	}

	dstHost, policy, failed, blocked, _ := s.policyEvaluator.genPolicy(logger, originHost, isIP, false)
	if failed {
		sendReply(logger, cliConn, socks5ReplyServerFailure)
		return
	}
	if blocked {
		logger.Info("Connection blocked: ", originHost)
		sendReply(logger, cliConn, socks5ReplyConnNotAllowed)
		return
	}

	portBytes, err := readN(cliConn, buf[:2])
	if err != nil {
		logger.Error("Read port: ", err)
		return
	}
	dstPort := binary.BigEndian.Uint16(portBytes)
	putBuffer.do()
	originPort := F.Uint(dstPort)
	oldTarget := net.JoinHostPort(originHost, originPort)

	logger.Info("CONNECT ", oldTarget)
	logger.Info("Policy:", policy)
	if policy.Port != 0 && policy.Port != unsetInt {
		dstPort = uint16(policy.Port)
	}

	port := F.Uint(dstPort)
	if !policy.ReplyFirst.IsTrue() {
		var err error
		dstConn, err = s.dialer.DialTimeout(dstHost, port, policy.ConnectTimeout, policy.DialDelay)
		if err != nil {
			logger.Error("Connection to ", oldTarget, " failed: ", err)
			sendReply(logger, cliConn, socks5ReplyServerFailure)
			return
		}
	}
	if !sendReply(logger, cliConn, socks5ReplySuccess) {
		return
	}

	closeConns.disarm()
	s.handleTunnel(&tunnelSession{
		logger:     logger,
		p:          policy,
		cliConn:    cliConn,
		dstConn:    dstConn,
		oldTarget:  oldTarget,
		target:     dstHost,
		originHost: originHost,
		originPort: originPort,
		port:       port,
	})
}

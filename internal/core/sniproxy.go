package core

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"

	F "github.com/lzpls/enimul/internal/fmt"
)

func (c *Core) SNIServe(cmdAddr, configAddr string) {
	listenAddr := cmdAddr
	if listenAddr == "" {
		listenAddr = configAddr
	}
	if listenAddr == "" || listenAddr == "none" {
		return
	}

	logger := c.newLogger("SP[00000]")
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Error("Failed to start SNI proxy server: ", err)
		return
	}
	defer ln.Close()
	addr := ln.Addr().String()
	logger.Info("SNI proxy server started at ", addr)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic("impossible")
	}

	var connID uint32
	for {
		conn, err := ln.Accept()
		if err == nil {
			connID += 1
			if connID > maxConnID {
				connID = 1
			}
			go c.handleTunnelSNI(conn, connID, port)
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Temporary() {
			logger.Warn("Accept failed: ", err)
		} else {
			logger.Error("Accept failed (fatal): ", err)
			return
		}
	}
}

func (c *Core) handleTunnelSNI(conn net.Conn, connID uint32, port string) {
	closeHere := true
	defer func() {
		if closeHere {
			conn.Close()
		}
	}()

	logger := c.newLogger(F.ConnIDToHex5("SP", connID))
	logger.Info("Connection from ", conn.RemoteAddr())

	br := bufio.NewReader(conn)
	header, err := br.Peek(5)
	if err != nil {
		if len(header) == 0 && errors.Is(err, io.EOF) {
			logger.Error("Empty tunnel")
		} else {
			logger.Error("Peek header: ", err)
		}
		return
	}

	if header[0] != tlsRecordTypeHandshake || header[1] != tlsMajorVersion {
		logger.Error("Not a standard TLS ClientHello")
		return
	}

	ts := &tunnelSession{
		logger:       logger,
		p:            &Policy{SniffOverrideMode: SniffOverrideAlways},
		cliConn:      conn,
		originPort:   port,
		fromSNIProxy: true,
	}
	payloadLen := 5 + int(binary.BigEndian.Uint16(header[3:5]))
	if !c.handleTLS(ts, payloadLen, br) || !drainBuffered(logger, br, ts.dstConn) {
		return
	}

	closeHere = false
	forward(logger, conn, ts.dstConn, ts.originHost)
}

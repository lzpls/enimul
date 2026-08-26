package core

import (
	"context"
	"io"
	"maps"
	"net"
	"net/http"

	F "github.com/lzpls/enimul/internal/fmt"
	"github.com/lzpls/enimul/internal/log"
)

const (
	status500 = "500 Internal Server Error"
	status403 = "403 Forbidden"
	status502 = "502 Bad Gateway"
)

var defaultHTTPTransport = http.DefaultTransport.(*http.Transport)

func init() { defaultHTTPTransport.Proxy = nil }

func (c *Core) getHTTPConnID() uint32 {
	for {
		old := c.httpConnID.Load()
		new := old + 1
		if new > maxConnID {
			new = 1
		}
		if c.httpConnID.CompareAndSwap(old, new) {
			return new
		}
	}
}

func (c *Core) HTTPServe(ctx context.Context, cmdAddr, configAddr string) {
	listenAddr := cmdAddr
	if listenAddr == "" {
		listenAddr = configAddr
	}
	if listenAddr == "" {
		F.Println("HTTP bind address is not specified")
		return
	}
	if listenAddr == "none" {
		return
	}

	logger := c.newLogger("H[00000]")
	ln, err := listenTCP(listenAddr)
	if err != nil {
		logger.Error("Failed to start HTTP proxy server: ", err)
		return
	}
	c.httpListener = ln
	c.httpConnTracker = newConnTracker()
	logger.Info("HTTP proxy server started at ", ln.Addr())
	srv := &http.Server{
		Handler:     http.HandlerFunc(c.httpHandler),
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}
	c.httpServer = srv
	if err := srv.Serve(ln); err != nil {
		logger.Error("HTTP serve: ", err)
	}
}

func (c *Core) httpHandler(w http.ResponseWriter, req *http.Request) {
	logger := c.newLogger(F.ConnIDToHex5("H", c.getHTTPConnID()))
	logger.Info(req.RemoteAddr, " - \"", req.Method, " ", req.RequestURI, " ", req.Proto, "\"")

	if req.Method == http.MethodConnect {
		c.handleHTTPConnect(logger, w, req)
		return
	}

	if !req.URL.IsAbs() {
		logger.Error("URI not fully qualified")
		http.Error(w, status403, http.StatusForbidden)
		return
	}

	c.forwardHTTPRequest(logger, w, req)
}

func (c *Core) handleHTTPConnect(logger log.Logger, w http.ResponseWriter, req *http.Request) {
	oldDest := req.Host
	if oldDest == "" {
		logger.Error("Empty host")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	originHost, originPort, err := net.SplitHostPort(oldDest)
	if err != nil {
		logger.Error("Split ", oldDest, " failed: ", err)
		return
	}

	ctx := req.Context()
	dstHost, policy, fail, blocked, _ := c.genPolicy(ctx, logger, originHost, false, false)
	if fail {
		http.Error(w, status500, http.StatusInternalServerError)
		return
	}
	if blocked {
		logger.Info("Connection blocked: ", originHost)
		http.Error(w, status403, http.StatusForbidden)
		return
	}

	logger.Info("Policy: ", policy)

	if policy.Mode == ModeBlock {
		http.Error(w, status403, http.StatusForbidden)
		return
	}

	dstPort := originPort
	if policy.Port != 0 && policy.Port != unsetInt {
		dstPort = F.Int(policy.Port)
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("Hijacking not supported")
		http.Error(w, status500, http.StatusInternalServerError)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		logger.Error("Hijack: ", err)
		http.Error(w, status500, http.StatusInternalServerError)
		return
	}
	cliConn := conn.(*net.TCPConn)
	c.httpConnTracker.addConn(cliConn)
	closeHere := true
	defer func() {
		if closeHere {
			cliConn.Close()
			c.httpConnTracker.removeConn(cliConn)
		}
	}()

	var dstConn *net.TCPConn
	if !policy.ReplyFirst.IsTrue() {
		dstConn, err = c.dialer.DialTimeoutMulti(ctx, dstHost, dstPort, policy.ConnectTimeout, policy.DialDelay)
		if err != nil {
			logger.Error("Connection to ", oldDest, " failed: ", err)
			_, err = cliConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			if err != nil {
				logger.Error("Send 502: ", err)
			}
			return
		}
		c.httpConnTracker.addConn(dstConn)
		defer func() {
			if closeHere {
				dstConn.Close()
				c.httpConnTracker.removeConn(dstConn)
			}
		}()
	}
	_, err = cliConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		logger.Error("Send 200: ", err)
		return
	}

	closeHere = false
	c.handleTunnel(&tunnelSession{
		ctx:         ctx,
		connTracker: c.httpConnTracker,
		logger:      logger,
		p:           policy,
		cliConn:     cliConn,
		dstConn:     dstConn,
		oldTarget:   oldDest,
		target:      dstHost,
		originHost:  originHost,
		originPort:  originPort,
		port:        dstPort,
	})
}

func (c *Core) forwardHTTPRequest(logger log.Logger, w http.ResponseWriter, originReq *http.Request) {
	if originReq.URL.Scheme != "http" {
		logger.Error("Invalid URL scheme: ", originReq)
		return
	}

	host := originReq.URL.Host
	if host == "" {
		logger.Error("Cannot determine target host")
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}

	originHost, port, err := net.SplitHostPort(host)
	if err != nil {
		originHost = host
		port = "80"
	}

	dstHost, p, failed, blocked, _ := c.genPolicy(originReq.Context(), logger, originHost, false, false)
	if failed {
		http.Error(w, status500, http.StatusInternalServerError)
		return
	}
	if blocked {
		logger.Info("Connection blocked: ", originHost)
		http.Error(w, status403, http.StatusForbidden)
		return
	}

	if p.HttpStatus != 0 && p.HttpStatus != unsetInt {
		if p.HttpStatus == 301 || p.HttpStatus == 302 {
			location := "https://" + host + originReq.URL.RequestURI()
			w.Header().Set("Location", location)
		}
		w.WriteHeader(p.HttpStatus)
		logger.Info("Sent ", p.HttpStatus, " ", http.StatusText(p.HttpStatus))
		return
	}

	dstPort := port
	if p.Port != 0 && p.Port != unsetInt {
		dstPort = F.Int(p.Port)
	}

	outReq := originReq.Clone(context.Background())
	outReq.Host = originReq.Host

	outReq.Header.Del("Connection")
	outReq.Header.Del("Keep-Alive")
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("TE")
	outReq.Header.Del("Trailer")
	outReq.Header.Del("Transfer-Encoding")
	outReq.Header.Del("Upgrade")

	transport := defaultHTTPTransport.Clone()
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return c.dialer.DialTimeoutMulti(ctx, dstHost, dstPort, p.ConnectTimeout, p.DialDelay)
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		logger.Error("RoundTrip failed: ", err)
		http.Error(w, status502, http.StatusBadGateway)
		return
	}
	logger.Info("Start forwarding")
	defer resp.Body.Close()

	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err = io.Copy(w, resp.Body); err != nil {
		logger.Error("Copy response body: ", err)
	}
}

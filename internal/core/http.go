package core

import (
	"context"
	"encoding/base64"
	"io"
	"maps"
	"net"
	"net/http"
	"strings"

	F "github.com/lzpls/enimul/internal/fmt"
	"github.com/lzpls/enimul/internal/log"
)

const (
	status500 = "500 Internal Server Error"
	status403 = "403 Forbidden"
	status502 = "502 Bad Gateway"
)

var defaultHTTPTransport = http.DefaultTransport.(*http.Transport).Clone()

func init() { defaultHTTPTransport.Proxy = nil }

func (s *Server) getHTTPConnID() uint32 {
	for {
		old := s.httpConnID.Load()
		new := old + 1
		if new > maxConnID {
			new = 1
		}
		if s.httpConnID.CompareAndSwap(old, new) {
			return new
		}
	}
}

func (s *Server) serveHTTPProxy(listenAddr string) {
	logger := s.logFactory.NewLogger("H[00000]")
	ln, err := listenTCP(listenAddr)
	if err != nil {
		logger.Error("Failed to start HTTP proxy server: ", err)
		return
	}
	logger.Info("HTTP proxy server started at ", ln.Addr())
	server := http.Server{Handler: http.HandlerFunc(s.httpHandler)}
	defer server.Close()
	if err := server.Serve(ln); err != nil {
		logger.Error("HTTP serve: ", err)
	}
}

func (s *Server) httpHandler(w http.ResponseWriter, req *http.Request) {
	logger := s.logFactory.NewLogger(F.ConnIDToHex5("H", s.getHTTPConnID()))
	logger.Info(req.RemoteAddr, " - \"", req.Method, " ", req.RequestURI, " ", req.Proto, "\"")

	if s.InboundAuth != nil {
		auth := req.Header.Get("Proxy-Authorization")
		if auth == "" {
			rejectHTTPProxyAuth(logger, w, "missing Proxy-Authorization header")
			return
		}

		scheme, encoded, ok := strings.Cut(auth, " ")
		if !ok || !strings.EqualFold(scheme, "Basic") || encoded == "" {
			rejectHTTPProxyAuth(logger, w, "expected Basic credentials in Proxy-Authorization header")
			return
		}

		credentials, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			rejectHTTPProxyAuth(logger, w, "invalid base64 credentials")
			return
		}

		username, password, ok := strings.Cut(string(credentials), ":")
		if !ok {
			rejectHTTPProxyAuth(logger, w, "vredentials must contain a username and password separated by ':'")
			return
		}

		if !s.InboundAuth.check(username, password) {
			rejectHTTPProxyAuth(logger, w, "invalid username or password")
			return
		}
	}

	if req.Method == http.MethodConnect {
		s.handleHTTPConnect(logger, w, req)
		return
	}

	if !req.URL.IsAbs() {
		logger.Error("URI not fully qualified")
		http.Error(w, status403, http.StatusForbidden)
		return
	}

	s.forwardHTTPRequest(logger, w, req)
}

func (s *Server) handleHTTPConnect(logger log.Logger, w http.ResponseWriter, req *http.Request) {
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

	dstHost, policy, fail, blocked, _ := s.policyEvaluator.genPolicy(logger, originHost, false, false)
	if fail {
		http.Error(w, status500, http.StatusInternalServerError)
		return
	}
	if blocked {
		logger.Info("Connection blocked: ", originHost)
		http.Error(w, status403, http.StatusForbidden)
		return
	}

	logger.Info("Policy:", policy)

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
	cliConn, ok := conn.(*net.TCPConn)
	if !ok {
		logger.Error("Not a *net.TCPConn")
		http.Error(w, status500, http.StatusInternalServerError)
		conn.Close()
		return
	}
	var dstConn *net.TCPConn
	closeConns := deferred(func() {
		if dstConn != nil {
			dstConn.Close()
		}
		cliConn.SetLinger(0)
		conn.Close()
	})
	defer closeConns.do()

	if !policy.ReplyFirst.IsTrue() {
		dstConn, err = s.dialer.DialTimeout(dstHost, dstPort, policy.ConnectTimeout, policy.DialDelay)
		if err != nil {
			logger.Error("Connection to ", oldDest, " failed: ", err)
			if _, err = cliConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")); err != nil {
				logger.Error("Send 502: ", err)
			}
			return
		}
	}
	if _, err = cliConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		logger.Error("Send 200: ", err)
		return
	}

	closeConns.disarm()
	s.handleTunnel(&tunnelSession{
		logger:     logger,
		p:          policy,
		cliConn:    cliConn,
		dstConn:    dstConn,
		oldTarget:  oldDest,
		target:     dstHost,
		originHost: originHost,
		originPort: originPort,
		port:       dstPort,
	})
}

func (s *Server) forwardHTTPRequest(logger log.Logger, w http.ResponseWriter, originReq *http.Request) {
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

	dstHost, p, failed, blocked, _ := s.policyEvaluator.genPolicy(logger, originHost, false, false)
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
		return s.dialer.DialContextTimeout(ctx, dstHost, dstPort, p.ConnectTimeout, p.DialDelay)
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		logger.Error("RoundTrip failed: ", err)
		http.Error(w, status502, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	logger.Info("Start forwarding")

	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err = io.Copy(w, resp.Body); err != nil {
		logger.Error("Copy response body: ", err)
	}
}

func rejectHTTPProxyAuth(logger log.Logger, w http.ResponseWriter, reason string) {
	logger.Error("Authentication failed: ", reason)
	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
	http.Error(w, "407 Proxy Authentication Required", http.StatusProxyAuthRequired)
}

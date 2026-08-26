package core

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/lzpls/enimul/internal/addrtrie"
	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/log"
	"github.com/lzpls/enimul/internal/orderedmap"
	_ "github.com/lzpls/enimul/internal/platform"
)

const Version = "v0.4.2"

type Core struct {
	logger        log.Logger
	logLevel      log.Level
	dns           dnsFields
	ttl           ttlProbingFields
	ipPools       *orderedmap.Map[*IPPool]
	defaultPolicy Policy
	hostsMatcher  *addrtrie.DomainMatcher[*dial.Dst]
	domainMatcher *addrtrie.DomainMatcher[*Policy]
	ipv4Matcher   *addrtrie.IPv4Trie[*Policy]
	ipv6Matcher   *addrtrie.IPv6Trie[*Policy]
	httpConnID    atomic.Uint32

	logOutput           *os.File
	dialer              *dial.Dialer
	httpListener        *net.TCPListener
	httpConnTracker     *connTracker
	httpServer          *http.Server
	socks5Listener      *net.TCPListener
	socks5ConnTracker   *connTracker
	sniProxyListener    *net.TCPListener
	sniProxyConnTracker *connTracker
	closeIPPools        func()
	cancel              func()
}

func (c *Core) setLogOutput(out string) error {
	switch out {
	case "stderr":
		c.logOutput = os.Stderr
	case "", "stdout": // default
		c.logOutput = os.Stdout
	default:
		out = os.ExpandEnv(out)
		if dir := filepath.Dir(out); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return E.WithStr("create log directory", err)
			}
		}
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return E.WithStr("open log file", err)
		}
		c.logOutput = f
	}
	return nil
}

func (c *Core) newLogger(prefix string) log.Logger {
	return log.New(c.logOutput, prefix, c.logLevel)
}

func (c *Core) Cleanup() {
	c.dialer.Close()
	if c.closeIPPools != nil {
		c.closeIPPools()
	}
	c.logOutput.Sync()
	switch c.logOutput {
	case os.Stderr, os.Stdout:
	default:
		c.logOutput.Close()
	}
}

func (c *Core) StopListening() {
	c.httpListener.Close()
	c.socks5Listener.Close()
	c.sniProxyListener.Close()
}

func (c *Core) Wait(ctx context.Context) {
	var wg sync.WaitGroup
	if c.httpServer != nil {
		wg.Go(func() {
			c.httpServer.Shutdown(ctx)
			c.httpConnTracker.Wait()
		})
	}
	if c.socks5ConnTracker != nil {
		wg.Go(func() { c.socks5ConnTracker.Wait() })
	}
	if c.sniProxyConnTracker != nil {
		wg.Go(func() { c.sniProxyConnTracker.Wait() })
	}
	wg.Wait()
}

func (c *Core) WaitAndCleanup(ctx context.Context) {
	c.Wait(ctx)
	c.Cleanup()
}

func (c *Core) Close() {
	c.cancel()
	if c.socks5ConnTracker != nil {
		c.socks5ConnTracker.Close()
	}
	if c.sniProxyConnTracker != nil {
		c.sniProxyConnTracker.Close()
	}
	if c.httpServer != nil {
		c.httpServer.Close()
	}
	c.Cleanup()
}

func getRawConn(conn any) (syscall.RawConn, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil, E.New("not a syscall.Conn")
	}
	rawConn, err := sc.SyscallConn()
	return rawConn, E.WithStr("get raw conn", err)
}

func listenTCP(addrStr string) (*net.TCPListener, error) {
	addr, err := net.ResolveTCPAddr("tcp", addrStr)
	if err != nil {
		return nil, err
	}
	return net.ListenTCP("tcp", addr)
}

type connTracker struct {
	sync.Mutex
	activeConns map[*net.TCPConn]struct{}
	wg          sync.WaitGroup
	closed      bool
}

func newConnTracker() *connTracker {
	return &connTracker{activeConns: make(map[*net.TCPConn]struct{})}
}

func (s *connTracker) addConn(c *net.TCPConn) {
	s.Lock()
	defer s.Unlock()
	if s.closed {
		c.Close()
	} else if c != nil {
		s.wg.Add(1)
		s.activeConns[c] = struct{}{}
	}
}

func (s *connTracker) removeConn(c *net.TCPConn) {
	if c == nil {
		return
	}
	s.Lock()
	defer s.Unlock()
	delete(s.activeConns, c)
	s.wg.Done()
}

func (s *connTracker) removeConns(conns ...*net.TCPConn) {
	s.Lock()
	defer s.Unlock()
	valid := 0
	for _, c := range conns {
		if c != nil {
			valid--
			c.Close()
			delete(s.activeConns, c)
		}
	}
	s.wg.Add(valid)
}

func (s *connTracker) Wait() {
	s.wg.Wait()
}

func (s *connTracker) Close() {
	s.Lock()
	defer s.Unlock()
	for c := range s.activeConns {
		if c != nil {
			c.Close()
			delete(s.activeConns, c)
		}
	}
}

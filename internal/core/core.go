package core

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"github.com/lzpls/enimul/internal/addrtrie"
	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/log"
	_ "github.com/lzpls/enimul/internal/platform"
)

const Version = "v0.6.2"

type Core struct {
	logLevel      log.Level
	logOutput     io.Writer
	dialer        *dial.Dialer
	dns           dnsFields
	ttl           ttlProbingFields
	ipPools       map[string]*IPPool
	defaultPolicy Policy
	hostsMatcher  *addrtrie.DomainMatcher[*dial.Dst]
	domainMatcher *addrtrie.DomainMatcher[*Policy]
	ipv4Matcher   *addrtrie.IPv4Trie[*Policy]
	ipv6Matcher   *addrtrie.IPv6Trie[*Policy]
	httpConnID    atomic.Uint32
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

func getRawConn[T syscall.Conn](conn T) (syscall.RawConn, error) {
	rawConn, err := conn.SyscallConn()
	return rawConn, E.WithStr("get raw conn", err)
}

func listenTCP(addrStr string) (*net.TCPListener, error) {
	addr, err := net.ResolveTCPAddr("tcp", addrStr)
	if err != nil {
		return nil, err
	}
	return net.ListenTCP("tcp", addr)
}

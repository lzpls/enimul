package core

import (
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"github.com/lzpls/enimul/internal/addrtrie"
	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/log"
	"github.com/lzpls/enimul/internal/orderedmap"
	_ "github.com/lzpls/enimul/internal/platform"
)

const Version = "v0.4.0-alpha.8"

type Core struct {
	logLevel      log.Level
	logOutput     io.Writer
	dialer        *dial.Dialer
	dns           dnsFields
	ttl           ttlProbingFields
	ipPools       *orderedmap.Map[*IPPool]
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

func getRawConn(conn any) (syscall.RawConn, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil, E.New("not a syscall.Conn")
	}
	rawConn, err := sc.SyscallConn()
	return rawConn, E.WithStr("get raw conn", err)
}

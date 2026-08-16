//go:build !windows && !linux

package core

import (
	"net"
	"net/netip"
	"time"

	E "github.com/lzpls/enimul/internal/errors"
	F "github.com/lzpls/enimul/internal/fmt"
	"github.com/lzpls/enimul/internal/log"
)

var errTTLDNotSupported = E.New("`ttl-d` is not supported on current system")

type TTLProbingConfig = struct{}

type ttlProbingFields = struct{}

func (c *Core) setTTLProbing(TTLProbingConfig) error {
	F.Println("Warning:", errTTLDNotSupported)
	return nil
}

func (c *Core) getFakeTTL(log.Logger, *Policy, netip.AddrPort) (int, error) {
	return unsetInt, errTTLDNotSupported
}

func desyncSend(net.Conn, []byte, int, int, int, time.Duration) error {
	return errTTLDNotSupported
}

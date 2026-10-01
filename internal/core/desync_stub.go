//go:build !windows && !linux

package core

import (
	"net"
	"net/netip"
	"time"

	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	F "github.com/lzpls/enimul/internal/fmt"
	"github.com/lzpls/enimul/internal/log"
)

var errTTLDNotSupported = E.New("`ttl-d` is not supported on current system")

type (
	TTLProbingConfig = struct{}
	ttlProbeManager  struct{}
)

func newTTLDesyncManager(*TTLProbingConfig, *dial.Dialer) (*ttlProbeManager, error) {
	F.Errln("Warning:", errTTLDNotSupported)
	return &ttlProbeManager{}, nil
}

func (*ttlProbeManager) getFakeTTL(log.Logger, *Policy, netip.AddrPort) (int, error) {
	return unsetInt, errTTLDNotSupported
}

func desyncSend(*net.TCPConn, []byte, int, int, int, time.Duration) error {
	return errTTLDNotSupported
}

//go:build !windows && !linux

package core

import (
	"net"
	"time"

	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/freelru"
	"github.com/lzpls/enimul/internal/log"
	"github.com/lzpls/enimul/internal/singleflight"
)

var errTTLDNotSupported = E.New("`ttl-d` is not supported on current system")

var (
	ttlCache        *freelru.ShardedLRU[string, int]
	ttlCacheTTL     time.Duration
	ttlSingleflight *singleflight.Group[string, int]
)

func loadTTLRules(string) error {
	return nil
}

func getFakeTTL(log.Logger, *Policy, string, bool) (int, error) {
	return unsetInt, errTTLDNotSupported
}

func desyncSend(net.Conn, bool, []byte, int, int, int, time.Duration) error {
	return errTTLDNotSupported
}

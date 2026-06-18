//go:build windows || linux

package core

import (
	"net"
	"sort"
	"syscall"
	"time"

	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	F "github.com/lzpls/enimul/internal/fmt"
	"github.com/lzpls/enimul/internal/freelru"
	"github.com/lzpls/enimul/internal/log"
	"github.com/lzpls/enimul/internal/platform"
	"github.com/lzpls/enimul/internal/singleflight"
)

const minInterval = 100 * time.Millisecond

var (
	calcTTL         func(int) (int, error)
	ttlCache        *freelru.ShardedLRU[string, int]
	ttlCacheTTL     time.Duration
	ttlSingleflight *singleflight.Group[string, int]
)

type timeoutError interface {
	Timeout() bool
}

type ttlRule struct {
	threshold int
	typ       byte
	val       int
}

func parseTTLRules(conf string) ([]ttlRule, error) {
	b := []byte(conf)
	var rules []ttlRule
	i := 0
	for i < len(b) {
		start := i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if start == i {
			return nil, E.New("invalid rule: missing left number")
		}
		a := 0
		for _, c := range b[start:i] {
			a = a*10 + int(c-'0')
		}

		if i >= len(b) {
			return nil, E.New("invalid rule: missing operator")
		}
		op := b[i]
		if op != '-' && op != '=' {
			return nil, E.New("invalid operator")
		}
		i++

		start = i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if start == i {
			return nil, E.New("invalid rule: missing right number")
		}
		val := 0
		for _, c := range b[start:i] {
			val = val*10 + int(c-'0')
		}

		rules = append(rules, ttlRule{
			threshold: a,
			typ:       op,
			val:       val,
		})

		if i < len(b) && b[i] == ';' {
			i++
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].threshold > rules[j].threshold
	})
	return rules, nil
}

func loadTTLRules(conf string) error {
	if conf == "" {
		calcTTL = func(ttl int) (int, error) { return ttl - 1, nil }
		return nil
	}
	rules, err := parseTTLRules(conf)
	if err != nil {
		return E.WithStr("parse TTL rules", err)
	}
	calcTTL = func(ttl int) (int, error) {
		for _, r := range rules {
			if ttl >= r.threshold {
				if r.typ == '-' {
					return ttl - r.val, nil
				}
				// r.typ == '='
				return r.val, nil
			}
		}
		return 0, E.New("no matching TTL rule")
	}
	return nil
}

func getMinimumReachableTTL(addr string, ipv6 bool, maxTTL, attempts int, dialTimeout time.Duration) (int, bool, error) {
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, false, err
	}

	if ttlCache != nil {
		if ttl, ok := ttlCache.Get(ip); ok {
			return ttl, true, nil
		}
	}

	found := unsetInt
	if ttlSingleflight != nil {
		found, err, _ = ttlSingleflight.Do(addr, func() (int, error) {
			return probeMinimumReachableTTL(ip, addr, ipv6, maxTTL, attempts, dialTimeout)
		})
	} else {
		found, err = probeMinimumReachableTTL(ip, addr, ipv6, maxTTL, attempts, dialTimeout)
	}
	return found, false, err
}

func getFakeTTL(logger log.Logger, p *Policy, addr string, ipv6 bool) (ttl int, err error) {
	if p.FakeTTL == 0 || p.FakeTTL == unsetInt {
		var cached bool
		ttl, cached, err = getMinimumReachableTTL(addr, ipv6, p.MaxTTL, p.Attempts, p.SingleTimeout)
		if err != nil {
			return unsetInt, E.WithStr("detect minimum reachable TTL", err)
		}
		if ttl == unsetInt {
			return unsetInt, E.New("reachable TTL not found")
		}
		ttl, err = calcTTL(ttl)
		if err != nil {
			return unsetInt, E.WithStr("calculate fake TTL", err)
		}
		if logger != nil {
			if cached {
				logger.Info("Fake TTL for ", addr, " (cached): ", ttl)
			} else {
				logger.Info("Fake TTL for ", addr, ": ", ttl)
			}
		}
	} else {
		ttl = p.FakeTTL
	}
	return
}

func ttlLevelOption(isIPv6 bool) (int, int) {
	if isIPv6 {
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}

func probeMinimumReachableTTL(
	ip, addr string, isIPv6 bool,
	maxTTL, attempts int,
	dialTimeout time.Duration,
) (int, error) {
	level, opt := ttlLevelOption(isIPv6)
	dialer := dial.NewDialer(isIPv6)
	dialer.Timeout = dialTimeout

	low, high := 1, maxTTL
	found := unsetInt

	for low <= high {
		mid := (low + high) / 2
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			var innerErr error
			if err := c.Control(func(fd uintptr) {
				innerErr = syscall.SetsockoptInt(platform.FD(fd), level, opt, mid)
			}); err != nil {
				return E.WithStr("raw control", err)
			}
			return innerErr
		}
		var ok bool
		for range attempts {
			conn, err := dialer.Dial("tcp", addr)
			if err == nil {
				conn.Close()
				ok = true
				break
			}
			if te, ok := err.(timeoutError); !ok || !te.Timeout() {
				return unsetInt, E.WithStr("dial with TTL "+F.Int(mid), err)
			}
		}
		if ok {
			found = mid
			high = mid - 1
		} else {
			low = mid + 1
		}
	}

	if ttlCache != nil && found != unsetInt {
		ttlCache.AddWithLifetime(ip, found, ttlCacheTTL)
	}
	return found, nil
}

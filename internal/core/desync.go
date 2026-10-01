//go:build windows || linux

package core

import (
	"context"
	"hash/maphash"
	"net"
	"net/netip"
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

type ttlProbeManager struct {
	dialer          *dial.Dialer
	calcTTL         func(int) (int, error)
	ttlCache        *freelru.ShardedLRU[netip.Addr, int]
	ttlProbingGroup *singleflight.Group[netip.AddrPort, int]
}

type TTLProbingConfig struct {
	FakeTTLRules  string `json:"fake_ttl_rules"`
	SingleFlight  bool   `json:"singleflight"`
	DisableCache  bool   `json:"disable_cache"`
	CacheCapacity uint32 `json:"cache_capacity"`
}

func buildHashFunc[K comparable]() freelru.HashKeyCallback[K] {
	seed := maphash.MakeSeed()
	return func(k K) uint32 { return uint32(maphash.Comparable(seed, k)) }
}

func newTTLDesyncManager(conf *TTLProbingConfig, dialer *dial.Dialer) (*ttlProbeManager, error) {
	m := &ttlProbeManager{dialer: dialer}
	var err error
	if m.calcTTL, err = genTTLCalcFunc(conf.FakeTTLRules); err != nil {
		return nil, err
	}
	if !conf.DisableCache {
		if conf.CacheCapacity == 0 {
			conf.CacheCapacity = 1024
		}
		m.ttlCache, err = freelru.NewSharded[netip.Addr, int](conf.CacheCapacity, buildHashFunc[netip.Addr]())
		if err != nil {
			return nil, E.WithStr("init cache", err)
		}
	}
	if conf.SingleFlight {
		m.ttlProbingGroup = new(singleflight.Group[netip.AddrPort, int])
	}
	return m, nil
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

func genTTLCalcFunc(rulesStr string) (func(int) (int, error), error) {
	if rulesStr == "" {
		return func(ttl int) (int, error) { return ttl - 1, nil }, nil
	}
	rules, err := parseTTLRules(rulesStr)
	if err != nil {
		return nil, E.WithStr("parse ttl rules", err)
	}
	return func(ttl int) (int, error) {
		for _, r := range rules {
			if ttl >= r.threshold {
				if r.typ == '-' {
					return ttl - r.val, nil
				}
				// r.typ == '='
				return r.val, nil
			}
		}
		return 0, E.New("no matching ttl rule")
	}, nil
}

func (m *ttlProbeManager) getMinimumReachableTTL(addr netip.AddrPort, maxTTL, attempts int, dialTimeout, cacheTTL time.Duration) (int, bool, error) {
	if m.ttlCache != nil {
		if ttl, ok := m.ttlCache.Get(addr.Addr().Unmap()); ok {
			return ttl, true, nil
		}
	}

	ttl := -1
	var err error
	if m.ttlProbingGroup != nil {
		ttl, err, _ = m.ttlProbingGroup.Do(addr, func() (int, error) {
			return m.probeMinimumReachableTTL(addr, maxTTL, attempts, dialTimeout, cacheTTL)
		})
	} else {
		ttl, err = m.probeMinimumReachableTTL(addr, maxTTL, attempts, dialTimeout, cacheTTL)
	}
	return ttl, false, err
}

func (m *ttlProbeManager) getFakeTTL(logger log.Logger, p *Policy, addr netip.AddrPort) (int, error) {
	if p.FakeTTL != 0 && p.FakeTTL != unsetInt {
		return p.FakeTTL, nil
	}
	ttl, cached, err := m.getMinimumReachableTTL(addr, p.MaxTTL, p.Attempts, p.SingleTimeout, p.TTLCacheTTL)
	if err != nil {
		return -1, E.WithStr("get minimum reachable ttl", err)
	}
	if ttl == unsetInt {
		return -1, E.New("reachable ttl not found")
	}
	if ttl, err = m.calcTTL(ttl); err != nil {
		return -1, E.WithStr("calculate fake ttl", err)
	}
	if logger != nil {
		if cached {
			logger.Info("Fake TTL for ", addr, " (cached): ", ttl)
		} else {
			logger.Info("Fake TTL for ", addr, ": ", ttl)
		}
	}
	return ttl, nil
}

func ttlLevelOption(isIPv6 bool) (int, int) {
	if isIPv6 {
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}

func (m *ttlProbeManager) probeMinimumReachableTTL(
	raddr netip.AddrPort,
	maxTTL, attempts int,
	dialTimeout, cacheTTL time.Duration,
) (int, error) {
	type timeoutError interface {
		Timeout() bool
	}

	ip := raddr.Addr().Unmap()
	isIPv6 := ip.Is6()
	level, opt := ttlLevelOption(isIPv6)
	dialer := net.Dialer{Timeout: dialTimeout}

	low, high := 1, maxTTL
	found := -1

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
			conn, err := dialer.DialTCP(context.Background(), "tcp", m.dialer.GetLocalAddr(isIPv6), raddr)
			if err == nil {
				conn.Close()
				ok = true
				break
			}
			if te, ok := err.(timeoutError); !ok || !te.Timeout() {
				return unsetInt, E.WithStr("dial with ttl "+F.Int(mid), err)
			}
		}
		if ok {
			found = mid
			high = mid - 1
		} else {
			low = mid + 1
		}
	}

	if found != -1 && m.ttlCache != nil && cacheTTL != 0 && cacheTTL != unsetInt {
		m.ttlCache.AddWithLifetime(ip, found, cacheTTL)
	}
	return found, nil
}

func desyncSend(
	conn *net.TCPConn,
	record []byte, sniStart, sniLen int,
	fakeTTL int, fakeSleep time.Duration,
) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return err
	}

	isIPv6 := conn.RemoteAddr().(*net.TCPAddr).IP.To4() == nil
	level, opt := ttlLevelOption(isIPv6)
	var defaultTTL int
	var innerErr error
	if err = rawConn.Control(func(fd uintptr) {
		defaultTTL, innerErr = syscall.GetsockoptInt(platform.FD(fd), level, opt)
	}); err != nil {
		return E.WithStr("raw control", err)
	}
	if innerErr != nil {
		return E.WithStr("get default ttl", innerErr)
	}

	cut := findLastDotOrMidPos(record, sniStart, sniLen)
	fakeData := make([]byte, cut)
	copy(fakeData, record[:sniStart])
	const minInterval = 100 * time.Millisecond
	fakeSleep = max(minInterval, fakeSleep)

	if err = sendWithNoise(
		rawConn,
		fakeData, record[:cut],
		fakeTTL, defaultTTL,
		level, opt,
		fakeSleep,
	); err != nil {
		return E.WithStr("send data with noise", err)
	}
	if _, err = conn.Write(record[cut:]); err != nil {
		return E.WithStr("send remaining data", err)
	}
	return nil
}

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	F "github.com/lzpls/enimul/internal/fmt"
	"github.com/lzpls/enimul/internal/log"
)

const (
	unsetInt = -1
	//unsetString = "\x00"
)

type SniffOverrideMode uint8

const (
	SniffOverrideUnset SniffOverrideMode = iota
	SniffOverrideOff
	SniffOverrideAlways
	SniffOverridePolicyExists
	SniffOverrideRouteOnly
)

func (m *SniffOverrideMode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "off":
		*m = SniffOverrideOff
	case "always":
		*m = SniffOverrideAlways
	case "policy_exists":
		*m = SniffOverridePolicyExists
	case "route_only":
		*m = SniffOverrideRouteOnly
	default:
		return E.New("invalid sniff_override: " + s)
	}
	return nil
}

type Mode uint8

const (
	ModeUnset Mode = iota
	ModeRaw
	ModeDirect
	ModeTLSRF
	ModeTTLD
	ModeBlock
	ModeTLSAlert
	ModeDefault = ModeTLSRF
)

const (
	ModeNameRaw      = "raw"
	ModeNameDirect   = "direct"
	ModeNameTLSRF    = "tls-rf"
	ModeNameTTLD     = "ttl-d"
	ModeNameBlock    = "block"
	ModeNameTLSAlert = "tls-alert"
)

func (m *Mode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case ModeNameRaw:
		*m = ModeRaw
	case ModeNameDirect:
		*m = ModeDirect
	case ModeNameTLSRF:
		*m = ModeTLSRF
	case ModeNameTTLD:
		*m = ModeTTLD
	case ModeNameBlock:
		*m = ModeBlock
	case ModeNameTLSAlert:
		*m = ModeTLSAlert
	default:
		return E.New("invalid mode: " + s)
	}
	return nil
}

func (m Mode) String() string {
	switch m {
	case ModeRaw:
		return ModeNameRaw
	case ModeDirect:
		return ModeNameDirect
	case ModeTLSRF:
		return ModeNameTLSRF
	case ModeTTLD:
		return ModeNameTTLD
	case ModeBlock:
		return ModeNameBlock
	case ModeTLSAlert:
		return ModeNameTLSAlert
	}
	return "unknown"
}

type TriBool uint8

const (
	BoolUnset TriBool = iota
	BoolFalse
	BoolTrue
)

func (b TriBool) IsTrue() bool { return b == BoolTrue }

func (b TriBool) IsUnset() bool { return b == BoolUnset }

func (b *TriBool) UnmarshalJSON(data []byte) error {
	s := string(data)
	switch s {
	case "false":
		*b = BoolFalse
	case "true":
		*b = BoolTrue
	default:
		return E.New("invalid bool: " + s)
	}
	return nil
}

type Byte struct {
	b           byte
	valid, zero bool
}

func (b Byte) IsUnset() bool { return !b.valid }

func (b Byte) IsZero() bool { return b.IsUnset() || b.zero }

func (b Byte) Byte() byte { return b.b }

func (b *Byte) UnmarshalJSON(data []byte) error {
	b.valid = true
	if string(data) == "false" {
		b.zero = true
		return nil
	}
	if err := json.Unmarshal(data, &b.b); err != nil {
		return err
	}
	return nil
}

type Policy struct {
	ReplyFirst        TriBool
	SniffOverrideMode SniffOverrideMode
	DNSMode           DNSMode
	DNSCacheTTL       time.Duration
	ConnectTimeout    time.Duration
	DialDelay         time.Duration
	Host              dial.Dst
	MapTo             dial.Dst
	Port              int
	HttpStatus        int
	TLS13Only         TriBool
	Mode              Mode

	NumRecords   int
	NumSegments  int
	WaitForAck   TriBool
	OOB          TriBool
	OOBEx        TriBool
	MinorVer     Byte
	SendInterval time.Duration

	FakeTTL       int
	FakeSleep     time.Duration
	MaxTTL        int
	Attempts      int
	SingleTimeout time.Duration
	TTLCacheTTL   time.Duration
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	var tmp struct {
		SniffOverrideMode SniffOverrideMode `json:"sniff_override"`
		ReplyFirst        TriBool           `json:"reply_first"`
		ConnectTimeout    *string           `json:"connect_timeout"`
		DialDelay         *string           `json:"dial_delay"`
		Host              dial.Dst          `json:"host"`
		MapTo             dial.Dst          `json:"map_to"`
		Port              *uint16           `json:"port"`
		DNSMode           DNSMode           `json:"dns_mode"`
		DNSCacheTTL       *string           `json:"dns_cache_ttl"`
		HttpStatus        *uint             `json:"http_status"`
		TLS13Only         TriBool           `json:"tls13_only"`
		Mode              Mode              `json:"mode"`
		NumRecords        *uint             `json:"num_records"`
		NumSegments       *int              `json:"num_segs"`
		WaitForAck        TriBool           `json:"wait_for_ack"`
		OOB               TriBool           `json:"oob"`
		OOBEx             TriBool           `json:"oob_ex"`
		MinorVer          Byte              `json:"minor_ver"`
		SendInterval      *string           `json:"send_interval"`
		FakeTTL           *uint8            `json:"fake_ttl"`
		FakeSleep         *string           `json:"fake_sleep"`
		MaxTTL            *uint8            `json:"max_ttl"`
		Attempts          *uint             `json:"attempts"`
		SingleTimeout     *string           `json:"single_timeout"`
		TTLCacheTTL       *string           `json:"ttl_cache_ttl"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	p.SniffOverrideMode = tmp.SniffOverrideMode
	p.ReplyFirst = tmp.ReplyFirst
	p.TLS13Only = tmp.TLS13Only
	p.Mode = tmp.Mode
	p.DNSMode = tmp.DNSMode
	p.OOB = tmp.OOB
	p.OOBEx = tmp.OOBEx
	p.MinorVer = tmp.MinorVer
	p.WaitForAck = tmp.WaitForAck
	p.Host = tmp.Host
	p.MapTo = tmp.MapTo

	if tmp.Port == nil {
		p.Port = unsetInt
	} else {
		p.Port = int(*tmp.Port)
	}

	if tmp.HttpStatus == nil {
		p.HttpStatus = unsetInt
	} else {
		p.HttpStatus = int(*tmp.HttpStatus)
	}

	if tmp.NumRecords != nil {
		if *tmp.NumRecords == 0 {
			return E.New("num_records cannot be 0")
		}
		p.NumRecords = int(*tmp.NumRecords)
	}

	if tmp.NumSegments != nil {
		if *tmp.NumSegments == 0 {
			return E.New("num_segs cannot be 0")
		}
		p.NumSegments = *tmp.NumSegments
	}

	if tmp.FakeTTL == nil {
		p.FakeTTL = unsetInt
	} else {
		p.FakeTTL = int(*tmp.FakeTTL)
	}

	if tmp.Attempts != nil {
		if *tmp.Attempts == 0 {
			return E.New("attempts cannot be 0")
		}
		p.Attempts = int(*tmp.Attempts)
	}

	if tmp.MaxTTL != nil {
		if *tmp.MaxTTL == 0 {
			return E.New("max_ttl cannot be 0")
		}
		p.MaxTTL = int(*tmp.MaxTTL)
	}

	var err error
	if tmp.ConnectTimeout == nil {
		p.ConnectTimeout = unsetInt
	} else {
		p.ConnectTimeout, err = time.ParseDuration(*tmp.ConnectTimeout)
		if err != nil {
			return fmt.Errorf("parse connect_timeout %s: %w", *tmp.ConnectTimeout, err)
		}
		if p.ConnectTimeout <= 0 {
			return fmt.Errorf("connect_timeout %s: must be greater than 0", *tmp.ConnectTimeout)
		}
	}

	if tmp.DialDelay == nil {
		p.DialDelay = unsetInt
	} else {
		p.DialDelay, err = time.ParseDuration(*tmp.DialDelay)
		if err != nil {
			return fmt.Errorf("parse dial_delay %s: %w", *tmp.DialDelay, err)
		}
		if p.DialDelay <= 0 {
			return fmt.Errorf("dial_delay %s: must be greater than 0", *tmp.DialDelay)
		}
	}

	if tmp.SendInterval == nil {
		p.SendInterval = unsetInt
	} else {
		p.SendInterval, err = time.ParseDuration(*tmp.SendInterval)
		if err != nil {
			return fmt.Errorf("parse send_interval %s: %w", *tmp.SendInterval, err)
		}
		if p.SendInterval < 0 {
			return fmt.Errorf("send_interval %s: outside the valid range", *tmp.SendInterval)
		}
	}

	if tmp.FakeSleep != nil {
		p.FakeSleep, err = time.ParseDuration(*tmp.FakeSleep)
		if err != nil {
			return fmt.Errorf("parse fake_sleep %s: %w", *tmp.FakeSleep, err)
		}
		if p.FakeSleep <= 0 {
			return fmt.Errorf("fake_sleep %s: must be greater than 0", *tmp.FakeSleep)
		}
	}

	if tmp.SingleTimeout == nil {
		p.SingleTimeout = unsetInt
	} else {
		p.SingleTimeout, err = time.ParseDuration(*tmp.SingleTimeout)
		if err != nil {
			return fmt.Errorf("parse single_timeout %s: %w", *tmp.SingleTimeout, err)
		}
		if p.SingleTimeout <= 0 {
			return fmt.Errorf("single_timeout %s: must be greater than 0", *tmp.SingleTimeout)
		}
	}

	if tmp.DNSCacheTTL == nil {
		p.DNSCacheTTL = unsetInt
	} else {
		p.DNSCacheTTL, err = time.ParseDuration(*tmp.DNSCacheTTL)
		if err != nil {
			return fmt.Errorf("parse dns_cache_ttl %s: %w", *tmp.DNSCacheTTL, err)
		}
		if p.DNSCacheTTL < 0 {
			return fmt.Errorf("dns_cache_ttl %s: must be greater than -1", *tmp.DNSCacheTTL)
		}
	}

	if tmp.TTLCacheTTL == nil {
		p.TTLCacheTTL = unsetInt
	} else {
		p.TTLCacheTTL, err = time.ParseDuration(*tmp.TTLCacheTTL)
		if err != nil {
			return fmt.Errorf("parse ttl_cache_ttl %s: %w", *tmp.TTLCacheTTL, err)
		}
		if p.TTLCacheTTL < 0 {
			return fmt.Errorf("ttl_cache_ttl %s: must be greater than -1", *tmp.TTLCacheTTL)
		}
	}

	return nil
}

func (p *Policy) String() string {
	fields := make([]string, 0, 13)
	if p.ConnectTimeout != 0 {
		fields = append(fields, "timeout="+p.ConnectTimeout.String())
	}
	if p.Port != unsetInt && p.Port != 0 {
		fields = append(fields, "port="+F.Int(p.Port))
	}
	if p.Host.IsZero() {
		if p.DNSMode != DNSModeUnset {
			fields = append(fields, p.DNSMode.String())
		}
		if p.DNSCacheTTL > 0 {
			fields = append(fields, "dns_cache_ttl="+p.DNSCacheTTL.String())
		}
	}
	if p.HttpStatus > 0 {
		fields = append(fields, "http_status="+F.Int(p.HttpStatus))
	}
	if p.TLS13Only.IsTrue() {
		fields = append(fields, "tls13_only")
	}
	fields = append(fields, p.Mode.String())
	switch p.Mode {
	case ModeTLSRF:
		if !p.MinorVer.IsZero() {
			fields = append(fields, "minor_ver="+F.Uint(p.MinorVer.Byte()))
		}
		if p.NumRecords != unsetInt && p.NumRecords != 1 {
			fields = append(fields, "records="+F.Int(p.NumRecords))
		}
		if p.NumSegments != unsetInt && p.NumSegments != 1 {
			fields = append(fields, "segs="+F.Int(p.NumSegments))
		}
		if p.SendInterval > 0 {
			fields = append(fields, "send_interval="+p.SendInterval.String())
		}
		if p.OOB.IsTrue() {
			fields = append(fields, "oob")
		}
		if p.OOBEx.IsTrue() {
			fields = append(fields, "oob_ex")
		}
	case ModeTTLD:
		if p.FakeTTL == 0 || p.FakeTTL == unsetInt {
			fields = append(fields, "auto_fake_ttl")
			if p.Attempts != 0 {
				fields = append(fields, "attempts="+F.Int(p.Attempts))
			}
			if p.MaxTTL != 0 {
				fields = append(fields, "max_ttl="+F.Int(p.MaxTTL))
			}
			if p.SingleTimeout != 0 {
				fields = append(fields, "single_timeout="+p.SingleTimeout.String())
			}
			if p.TTLCacheTTL > 0 {
				fields = append(fields, "ttl_cache_ttl="+p.TTLCacheTTL.String())
			}
		} else {
			fields = append(fields, "fake_ttl="+F.Int(p.FakeTTL))
		}
		if p.FakeSleep != 0 {
			fields = append(fields, "fake_sleep="+p.FakeSleep.String())
		}
	}
	return strings.Join(fields, " ")
}

func mergePolicies(policies ...*Policy) *Policy {
	merged := Policy{
		Port:           unsetInt,
		DialDelay:      unsetInt,
		HttpStatus:     unsetInt,
		SendInterval:   unsetInt,
		FakeTTL:        unsetInt,
		ConnectTimeout: unsetInt,
		SingleTimeout:  unsetInt,
		DNSCacheTTL:    unsetInt,
		TTLCacheTTL:    unsetInt,
	}
	for _, p := range policies {
		if merged.SniffOverrideMode == SniffOverrideUnset && p.SniffOverrideMode != SniffOverrideUnset {
			merged.SniffOverrideMode = p.SniffOverrideMode
		}
		if merged.ReplyFirst.IsUnset() && !p.ReplyFirst.IsUnset() {
			merged.ReplyFirst = p.ReplyFirst
		}
		if merged.ConnectTimeout == unsetInt && p.ConnectTimeout != unsetInt {
			merged.ConnectTimeout = p.ConnectTimeout
		}
		if merged.DialDelay == unsetInt && p.DialDelay != unsetInt {
			merged.DialDelay = p.DialDelay
		}
		if merged.Host.IsZero() && !p.Host.IsZero() {
			merged.Host = p.Host
		}
		if merged.MapTo.IsZero() && !p.MapTo.IsZero() {
			merged.MapTo = p.MapTo
		}
		if merged.Port == unsetInt && p.Port != unsetInt {
			merged.Port = p.Port
		}
		if merged.HttpStatus == unsetInt && p.HttpStatus != unsetInt {
			merged.HttpStatus = p.HttpStatus
		}
		if merged.TLS13Only.IsUnset() && !p.TLS13Only.IsUnset() {
			merged.TLS13Only = p.TLS13Only
		}
		if merged.Mode == ModeUnset && p.Mode != ModeUnset {
			merged.Mode = p.Mode
		}
		if merged.DNSMode == DNSModeUnset && p.DNSMode != DNSModeUnset {
			merged.DNSMode = p.DNSMode
		}
		if merged.DNSCacheTTL == unsetInt && p.DNSCacheTTL != unsetInt {
			merged.DNSCacheTTL = p.DNSCacheTTL
		}
		if merged.NumRecords == 0 && p.NumRecords != 0 {
			merged.NumRecords = p.NumRecords
		}
		if merged.NumSegments == 0 && p.NumSegments != 0 {
			merged.NumSegments = p.NumSegments
		}
		if merged.WaitForAck.IsUnset() && !p.WaitForAck.IsUnset() {
			merged.WaitForAck = p.WaitForAck
		}
		if merged.OOB.IsUnset() && !p.OOB.IsUnset() {
			merged.OOB = p.OOB
		}
		if merged.OOBEx.IsUnset() && !p.OOBEx.IsUnset() {
			merged.OOBEx = p.OOBEx
		}
		if merged.MinorVer.IsUnset() && !p.MinorVer.IsUnset() {
			merged.MinorVer = p.MinorVer
		}
		if merged.SendInterval == unsetInt && p.SendInterval != unsetInt {
			merged.SendInterval = p.SendInterval
		}
		if merged.FakeSleep == 0 && p.FakeSleep != 0 {
			merged.FakeSleep = p.FakeSleep
		}
		if merged.FakeTTL == unsetInt && p.FakeTTL != unsetInt {
			merged.FakeTTL = p.FakeTTL
		}
		if merged.MaxTTL == 0 && p.MaxTTL != 0 {
			merged.MaxTTL = p.MaxTTL
		}
		if merged.Attempts == 0 && p.Attempts != 0 {
			merged.Attempts = p.Attempts
		}
		if merged.SingleTimeout == unsetInt && p.SingleTimeout != unsetInt {
			merged.SingleTimeout = p.SingleTimeout
		}
		if merged.TTLCacheTTL == unsetInt && p.TTLCacheTTL != unsetInt {
			merged.TTLCacheTTL = p.TTLCacheTTL
		}
	}
	if merged.Mode == ModeUnset {
		merged.Mode = ModeDefault
	}
	if merged.DNSMode == DNSModeUnset {
		merged.DNSMode = DNSModeDefault
	}
	return &merged
}

const (
	noRedirectPrefix = "^"
	ipPoolTagPrefix  = "$"
	resolvePrefix    = "?"
)

func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

func (c *Core) getIPPolicy(ip netip.Addr) (*Policy, bool) {
	if ip.Unmap().Is6() {
		return c.ipv6Matcher.Find(ip)
	}
	return c.ipv4Matcher.Find(ip)
}

type policyConn struct {
	*net.TCPConn
	core    *Core
	policy  *Policy
	handled bool
}

func (c *policyConn) Write(b []byte) (n int, err error) {
	if c.handled {
		return c.TCPConn.Write(b)
	}
	c.handled = true
	var sniStart, sniLen int
	var hasKeyShare bool
	_, sniStart, sniLen, hasKeyShare, _, err = parseClientHello(b)
	if err != nil {
		return
	}
	if c.policy.TLS13Only.IsTrue() && !hasKeyShare {
		return 0, E.New("not a TLS 1.3 ClientHello")
	}
	if sniStart == -1 {
		return c.TCPConn.Write(b)
	}
	switch c.policy.Mode {
	case ModeDirect, ModeRaw:
		return c.TCPConn.Write(b)
	case ModeTTLD:
		raddr := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		ttl, err := c.core.getFakeTTL(nil, c.policy, raddr)
		if err != nil {
			return 0, E.WithStr("get fake ttl", err)
		}
		if err = desyncSend(
			c.TCPConn, b,
			sniStart, sniLen, ttl, c.policy.FakeSleep,
		); err != nil {
			return 0, E.WithStr("ttl desync", err)
		}
	case ModeTLSRF:
		if err = sendRecords(c.TCPConn, b, sniStart, sniLen,
			c.policy.NumRecords, c.policy.NumSegments,
			c.policy.MinorVer,
			c.policy.OOB.IsTrue(), c.policy.OOBEx.IsTrue(),
			c.policy.WaitForAck.IsTrue(),
			c.policy.SendInterval); err != nil {
			return 0, E.WithStr("tls fragment", err)
		}
	}
	n = len(b)
	return
}

func (c *Core) genDoHDialFunc(dohURL *url.URL) (func(ctx context.Context, network, address string) (net.Conn, error), error) {
	if dohURL.Scheme != "https" || dohURL.Host == "" {
		return nil, E.New("invalid DoH URL")
	}

	originHost := dohURL.Hostname()
	dstPort := dohURL.Port()
	if dstPort == "" {
		dstPort = "443"
	}
	policy := &c.defaultPolicy

	var (
		finalDst                              *dial.Dst
		domainPolicy, ipPolicy                *Policy
		isIPPool, hasDomainPolicy, noRedirect bool
	)

	if ip, err := netip.ParseAddr(originHost); err == nil {
		ipPolicy, _ = c.getIPPolicy(ip)
		if ipPolicy != nil {
			policy = mergePolicies(ipPolicy, policy)
		}
		var err error
		finalDst, isIPPool, err = preMapIP(ip, &policy.MapTo)
		if err != nil {
			return nil, err
		}
	} else {
		domainPolicy, hasDomainPolicy = c.domainMatcher.Find(originHost)
		if hasDomainPolicy {
			policy = mergePolicies(domainPolicy, policy)
		}
		host := &policy.Host
		if host.IsMulti() {
			finalDst = host
			goto brk
		}
		var single string
		single, noRedirect = stripNoRedirectPrefix(host.Single())
		if host.IsZero() || single == "" {
			if hostFromHosts, ok := c.hostsMatcher.Find(originHost); ok {
				if hostFromHosts.IsMulti() {
					finalDst = hostFromHosts
					goto brk
				}
				single, noRedirect = stripNoRedirectPrefix(hostFromHosts.Single())
			}
		}
		switch {
		case single == "self" || single == "":
			finalDst = dial.NewSingleDst(originHost)
		case strings.HasPrefix(single, resolvePrefix):
			finalDst = dial.NewSingleDst(single[1:])
		case strings.HasPrefix(single, ipPoolTagPrefix):
			isIPPool = true
			finalDst = dial.NewSingleDst(single)
		default:
			ip, err := netip.ParseAddr(single)
			if err != nil {
				finalDst = dial.NewSingleDst(single)
				goto brk
			}
			ipPolicy, _ = c.getIPPolicy(ip)
			if ipPolicy == nil {
				finalDst = dial.NewSingleDst(single)
				goto brk
			}
			if ipPolicy.MapTo.IsMulti() {
				finalDst = &ipPolicy.MapTo
				goto brk
			}
			finalDst, isIPPool, err = preMapIP(ip, &ipPolicy.MapTo)
			if err != nil {
				return nil, err
			}
		}
	}

brk:
	if policy.Mode == ModeBlock || policy.Mode == ModeTLSAlert {
		return nil, E.New("DoH policy mode cannot be block or tls-alert")
	}
	if policy.Port != 0 && policy.Port != unsetInt {
		dstPort = F.Int(policy.Port)
	}

	if !isIPPool {
		return func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := c.dialer.DialTimeoutMulti(ctx, finalDst, dstPort, policy.ConnectTimeout, policy.DialDelay)
			if err != nil {
				return nil, err
			}
			return &policyConn{TCPConn: conn, core: c, policy: policy}, nil
		}, nil
	}
	tag := finalDst.Single()[1:]
	pool, err := c.getIPPool(tag)
	if err != nil {
		return nil, err
	}
	if noRedirect || pool.multi {
		return func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := c.dialer.DialTimeoutMulti(ctx, pool.Get(), dstPort, policy.ConnectTimeout, policy.DialDelay)
			if err != nil {
				return nil, err
			}
			return &policyConn{TCPConn: conn, core: c, policy: policy}, nil
		}, nil
	}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		final, ipPolicy, err := c.ipRedirect(nil, pool.Get().Single())
		if err != nil {
			return nil, E.WithStr("ip redirect", err)
		}
		var p *Policy
		if hasDomainPolicy {
			p = mergePolicies(domainPolicy, ipPolicy, &c.defaultPolicy)
		} else {
			p = mergePolicies(ipPolicy, &c.defaultPolicy)
		}
		switch p.Mode {
		case ModeBlock, ModeTLSAlert:
			return nil, E.New("connection blocked by policy")
		}
		var port string
		if p.Port != 0 && p.Port != unsetInt {
			port = F.Int(p.Port)
		} else {
			port = dstPort
		}
		conn, err := c.dialer.DialTimeoutMulti(ctx, final, port, p.ConnectTimeout, p.DialDelay)
		if err != nil {
			return nil, err
		}
		return &policyConn{TCPConn: conn, core: c, policy: p}, nil
	}, nil
}

func preMapIP(ip netip.Addr, mapTo *dial.Dst) (final *dial.Dst, isIPPool bool, err error) {
	if mapTo.IsZero() {
		return dial.NewSingleDst(ip.String()), false, nil
	}
	if mapTo.IsMulti() {
		return mapTo, false, nil
	}
	single := mapTo.Single()
	switch {
	case strings.HasPrefix(single, ipPoolTagPrefix):
		return mapTo, true, nil
	case strings.LastIndexByte(single, '/') != -1:
		single, err = transformIP(ip, single)
		if err != nil {
			return nil, false, err
		}
	}
	return mapTo, false, nil
}

func stripNoRedirectPrefix(s string) (string, bool) {
	if strings.HasPrefix(s, noRedirectPrefix) {
		return s[1:], true
	}
	return s, false
}

func (c *Core) genPolicy(
	ctx context.Context,
	logger log.Logger,
	originHost string,
	isIP, returnWhenDomainNotFound bool,
) (host *dial.Dst, p *Policy, failed, blocked, domainNotFound bool) {
	isIP = isIP || net.ParseIP(originHost) != nil
	if isIP {
		var ipPolicy *Policy
		var err error
		host, ipPolicy, err = c.ipRedirect(logger, originHost)
		if err != nil {
			logger.Error("IP redirect: ", err)
			return nil, nil, true, false, false
		}
		if ipPolicy == nil {
			p = &c.defaultPolicy
		} else {
			p = mergePolicies(ipPolicy, &c.defaultPolicy)
		}
		if p.Mode == ModeBlock {
			return nil, nil, false, true, false
		}
		return
	}

	domainPolicy, hasDomainPolicy := c.domainMatcher.Find(originHost)
	if hasDomainPolicy {
		if domainPolicy.Mode == ModeBlock {
			return nil, nil, false, true, false
		}
		p = mergePolicies(domainPolicy, &c.defaultPolicy)
	} else {
		p = &c.defaultPolicy
	}

	host = &p.Host
	if host.IsMulti() {
		return
	}

	single, noRedirect := stripNoRedirectPrefix(host.Single())
	fromHosts := false
	if host.IsZero() || single == "" {
		if hostFromHosts, ok := c.hostsMatcher.Find(originHost); ok {
			if hostFromHosts.IsMulti() {
				host = hostFromHosts
				return
			}
			fromHosts = true
			host = hostFromHosts
			single, noRedirect = stripNoRedirectPrefix(host.Single())
		} else if returnWhenDomainNotFound {
			return nil, nil, false, false, true
		}
	}

	if single == "self" {
		host = dial.NewSingleDst(originHost)
		return
	}

	fromDNS := false
	if single == "" {
		resolved, cached, err := c.dnsResolve(ctx, originHost, p.DNSMode, p.DNSCacheTTL)
		if err != nil {
			logger.Error("Resolve ", originHost, " failed: ", err)
			return nil, nil, true, false, false
		}
		prefix := "DNS: "
		if cached {
			prefix = "DNS (cached): "
		}
		logger.Info(prefix, originHost, " -> ", resolved)
		if resolved.IsMulti() {
			host = resolved
			return
		}
		single = resolved.Single()
		fromDNS = true
	}

	if strings.HasPrefix(single, resolvePrefix) {
		cname := single[1:]
		resolved, cached, err := c.dnsResolve(ctx, cname, p.DNSMode, p.DNSCacheTTL)
		if err != nil {
			logger.Error("Resolve ", originHost, " failed: ", err)
			return nil, nil, true, false, false
		}
		prefix := "DNS: "
		if cached {
			prefix = "DNS (cached): "
		}
		logger.Info(prefix, originHost, " -> ", cname, " -> ", resolved)
		if resolved.IsMulti() {
			host = resolved
			return
		}
		single = resolved.Single()
		fromDNS = true
	}

	if !fromDNS {
		logPrefix := "Host: "
		if fromHosts {
			logPrefix = "Host (from hosts): "
		}
		if strings.HasPrefix(single, ipPoolTagPrefix) {
			cur, err := c.getDstFromIPPool(single[1:])
			if err != nil {
				logger.Error(err)
				return nil, nil, true, false, false
			}
			logger.Info(logPrefix, originHost, " -> ", single, " -> ", cur)
			if cur.IsMulti() {
				host = cur
				return
			}
			single = cur.Single()
		} else {
			logger.Info(logPrefix, originHost, " -> ", single)
		}
	}

	if noRedirect {
		host = dial.NewSingleDst(single)
		return
	}

	mapped, ipPolicy, err := c.ipRedirect(logger, single)
	if err != nil {
		logger.Error("IP redirect: ", err)
		return nil, nil, true, false, false
	}
	host = mapped
	if ipPolicy == nil {
		return
	}
	if hasDomainPolicy {
		p = mergePolicies(domainPolicy, ipPolicy, &c.defaultPolicy)
	} else {
		p = mergePolicies(ipPolicy, &c.defaultPolicy)
	}
	if p.Mode == ModeBlock {
		return nil, nil, false, true, false
	}
	return
}

func (c *Core) ipRedirect(logger log.Logger, host string) (*dial.Dst, *Policy, error) {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return dial.NewSingleDst(host), nil, nil
	}
	policy, exists := c.getIPPolicy(ip)
	if !exists {
		return dial.NewSingleDst(host), nil, nil
	}
	if policy.MapTo.IsZero() {
		return dial.NewSingleDst(host), policy, nil
	}
	if policy.MapTo.IsMulti() {
		return &policy.MapTo, policy, nil
	}
	mapTo := policy.MapTo.Single()
	if mapTo == "" {
		return dial.NewSingleDst(host), policy, nil
	}
	if strings.HasPrefix(mapTo, ipPoolTagPrefix) {
		cur, err := c.getDstFromIPPool(mapTo[1:])
		if err != nil {
			return nil, nil, err
		}
		if logger != nil {
			logger.Info("Redirect: ", host, " -> ", mapTo, " -> ", cur)
		}
		return cur, policy, nil
	}
	if strings.LastIndexByte(mapTo, '/') != -1 {
		mapTo, err = transformIP(ip, mapTo)
		if err != nil {
			return nil, nil, err
		}
	}
	if logger != nil && host != mapTo {
		logger.Info("Redirect: ", host, " -> ", mapTo)
	}
	return dial.NewSingleDst(mapTo), policy, nil
}

func transformIP(ip netip.Addr, targetNetStr string) (string, error) {
	prefix, err := netip.ParsePrefix(targetNetStr)
	if err != nil {
		return "", E.WithStr("invalid target network", err)
	}

	if ip.Is4() != prefix.Addr().Is4() {
		return "", E.New("IP version mismatch between source IP and target network")
	}

	networkAddr := prefix.Masked().Addr()
	bits := prefix.Bits()

	var newIP netip.Addr
	if ip.Is4() {
		ipBytes := ip.As4()
		netBytes := networkAddr.As4()
		var newBytes [4]byte

		for i := range 4 {
			bitPos := uint8(i * 8)
			if bits >= int(bitPos+8) {
				newBytes[i] = netBytes[i]
			} else if bits <= int(bitPos) {
				newBytes[i] = ipBytes[i]
			} else {
				maskBits := uint8(bits) - bitPos
				mask := uint8(0xFF << (8 - maskBits))
				newBytes[i] = (netBytes[i] & mask) | (ipBytes[i] & ^mask)
			}
		}
		newIP = netip.AddrFrom4(newBytes)
	} else {
		ipBytes := ip.As16()
		netBytes := networkAddr.As16()
		var newBytes [16]byte

		for i := range 16 {
			bitPos := uint8(i * 8)
			if bits >= int(bitPos+8) {
				newBytes[i] = netBytes[i]
			} else if bits <= int(bitPos) {
				newBytes[i] = ipBytes[i]
			} else {
				maskBits := uint8(bits) - bitPos
				mask := uint8(0xFF << (8 - maskBits))
				newBytes[i] = (netBytes[i] & mask) | (ipBytes[i] & ^mask)
			}
		}
		newIP = netip.AddrFrom16(newBytes)
	}

	return newIP.String(), nil
}

package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/freelru"
	"github.com/lzpls/enimul/internal/singleflight"

	"github.com/cespare/xxhash/v2"
	"github.com/miekg/dns"
)

type DNSClient interface {
	Exchange(*dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type dnsExchangeFunc = func(req *dns.Msg) (resp *dns.Msg, err error)

type dnsFields = struct {
	client         DNSClient
	exchange       dnsExchangeFunc
	cache          *freelru.ShardedLRU[string, *dial.Dst]
	resolveGroup   *singleflight.Group[string, *dial.Dst]
	edns0SubnetOpt *dns.OPT
	qtype2         uint16
}

type DNSConfig struct {
	Type          string `json:"type"`
	Addr          string `json:"addr"`
	SingleFlight  bool   `json:"singleflight"`
	DisableCache  bool   `json:"disable_cache"`
	CacheCapacity uint32 `json:"cache_capacity"`
	EDNS0Subnet   string `json:"edns0_subnet"`

	UDPSize       uint16 `json:"udp_size"`
	ClientTimeout string `json:"client_timeout"`
	WaitTimeout   string `json:"wait_timeout"`
	MinRTT        string `json:"min_rtt"`
	Qtype2        string `json:"qtype2"`

	DoHOutbound string `json:"doh_outbound"`
}

func (c *Core) setDNS(conf DNSConfig) error {
	if conf.Addr == "" {
		return E.New("dns.addr cannot be empty")
	}

	addr := conf.Addr
	switch conf.Type {
	case "", "udp": // default
		if _, err := netip.ParseAddrPort(addr); err != nil {
			return E.WithStr("invalid dns.addr", err)
		}

		var cli dns.Client
		var err error
		if conf.UDPSize > 0 {
			cli.UDPSize = conf.UDPSize
		}
		if conf.ClientTimeout != "" {
			cli.Timeout, err = time.ParseDuration(conf.ClientTimeout)
			if err != nil {
				return E.WithStr("invalid dns.client_timeout", err)
			}
			if cli.Timeout <= 0 {
				return E.New("dns.client_timeout must be greater than 0")
			}
		}

		if conf.Qtype2 != "" {
			var ok bool
			c.dns.qtype2, ok = dns.StringToType[conf.Qtype2]
			if !ok {
				return fmt.Errorf("invalid dns.second_record_type %q", conf.Qtype2)
			}
		}

		var dnsClient DNSClient
		if conf.WaitTimeout == "" && conf.MinRTT == "" {
			dnsClient = &cli
		} else {
			var waitTimeout, minRTT time.Duration
			if conf.WaitTimeout != "" {
				waitTimeout, err = time.ParseDuration(conf.WaitTimeout)
				if err != nil {
					return E.WithStr("invalid dns.wait_timeout", err)
				}
				if waitTimeout <= 0 {
					return E.New("dns.wait_timeout must be greater than 0")
				}
			}
			if conf.MinRTT != "" {
				minRTT, err = time.ParseDuration(conf.MinRTT)
				if err != nil {
					return E.WithStr("invalid dns.min_rtt", err)
				}
				if minRTT <= 0 {
					return E.New("dns.min_rtt must be greater than 0")
				}
			}
			dnsClient = &antiHijackDNSClient{
				Client:      cli,
				waitTimeout: waitTimeout,
				minRTT:      minRTT,
			}
		}
		c.dns.exchange = buildDNSExchangeFunc(dnsClient, addr)
	case "tcp":
		if _, err := netip.ParseAddrPort(addr); err != nil {
			return E.WithStr("invalid dns.addr", err)
		}
		c.dns.exchange = buildDNSExchangeFunc(&dns.Client{Net: "tcp"}, addr)
	case "tls":
		if _, err := netip.ParseAddrPort(addr); err != nil {
			return E.WithStr("invalid dns.addr", err)
		}
		c.dns.exchange = buildDNSExchangeFunc(&dns.Client{Net: "tcp-tls"}, addr)
	case "https":
		dohURL, err := url.Parse(addr)
		if err != nil {
			return fmt.Errorf("invalid DoH URL %q: %w", addr, err)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		switch conf.DoHOutbound {
		case "", "policy": // default
			transport.Proxy = nil
			transport.DialContext, err = c.genDoHDialFunc(dohURL)
			if err != nil {
				return E.WithStr("generate DoH dial function", err)
			}
		case "direct":
			transport.Proxy = nil
		case "env":
		default:
			proxyURL, err := url.Parse(conf.DoHOutbound)
			if err != nil {
				return err
			}
			switch proxyURL.Scheme {
			case "http", "https", "socks5", "socks5h":
			case "":
				return E.New("proxy url scheme cannot be empty")
			default:
				return fmt.Errorf("invalid proxy url scheme: %q", proxyURL.Scheme)
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		}
		c.dns.exchange = buildDoHExchangeFunc(&http.Client{Transport: transport}, addr)
	default:
		return fmt.Errorf("unknown dns.type: %q", conf.Type)
	}

	if conf.SingleFlight {
		c.dns.resolveGroup = new(singleflight.Group[string, *dial.Dst])
	}

	if !conf.DisableCache {
		if conf.CacheCapacity == 0 {
			conf.CacheCapacity = 4096
		}
		var err error
		hashFunc := func(s string) uint32 { return uint32(xxhash.Sum64String(s)) }
		c.dns.cache, err = freelru.NewSharded[string, *dial.Dst](conf.CacheCapacity, hashFunc)
		if err != nil {
			return E.WithStr("init DNS cache", err)
		}
	}

	if conf.EDNS0Subnet != "" {
		prefix, err := netip.ParsePrefix(conf.EDNS0Subnet)
		if err != nil {
			return fmt.Errorf("invalid edns0_subnet %q: %w", conf.EDNS0Subnet, err)
		}
		family := uint16(1)
		if prefix.Addr().Unmap().Is6() {
			family = 2
		}
		edns0 := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        family,
			SourceNetmask: uint8(prefix.Bits()),
			Address:       prefix.Addr().AsSlice(),
		}
		c.dns.edns0SubnetOpt = &dns.OPT{
			Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
			Option: []dns.EDNS0{edns0},
		}
	}

	return nil
}

func buildDNSExchangeFunc(c DNSClient, addr string) dnsExchangeFunc {
	return func(req *dns.Msg) (resp *dns.Msg, err error) {
		resp, _, err = c.Exchange(req, addr)
		return resp, err
	}
}

func buildDoHExchangeFunc(httpClient *http.Client, addr string) dnsExchangeFunc {
	urlPrefix := addr + "?dns="
	return func(req *dns.Msg) (*dns.Msg, error) {
		wire, err := req.Pack()
		if err != nil {
			return nil, E.WithStr("pack dns request", err)
		}
		url := urlPrefix + base64.RawURLEncoding.EncodeToString(wire)
		httpReq, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, E.WithStr("build http request", err)
		}
		httpReq.Header.Set("Accept", "application/dns-message")
		httpResp, err := httpClient.Do(httpReq)
		if err != nil {
			return nil, E.WithStr("http request", err)
		}
		defer httpResp.Body.Close()
		if httpResp.StatusCode != http.StatusOK {
			return nil, E.New("bad http status: " + httpResp.Status)
		}
		respWire, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, E.WithStr("read http body", err)
		}
		resp := new(dns.Msg)
		if err = resp.Unpack(respWire); err != nil {
			return nil, E.WithStr("unpack dns response", err)
		}
		return resp, nil
	}
}

type DNSMode uint8

const (
	DNSModeUnset DNSMode = iota
	DNSModePreferIPv4
	DNSModePreferIPv6
	DNSModeIPv4Only
	DNSModeIPv6Only
	DNSModeMultiPreferIPv4
	DNSModeMultiPreferIPv6
	DNSModeMultiIPv4Only
	DNSModeMultiIPv6Only
	DNSModeDefault = DNSModePreferIPv4
)

const (
	DNSModeNamePreferIPv4      = "prefer_ipv4"
	DNSModeNamePreferIPv6      = "prefer_ipv6"
	DNSModeNameIPv4Only        = "ipv4_only"
	DNSModeNameIPv6Only        = "ipv6_only"
	DNSModeNameMultiPreferIPv4 = "multi_prefer_ipv4"
	DNSModeNameMultiPreferIPv6 = "multi_prefer_ipv6"
	DNSModeNameMultiIPv4Only   = "multi_ipv4_only"
	DNSModeNameMultiIPv6Only   = "multi_ipv6_only"
)

func (m DNSMode) String() string {
	switch m {
	case DNSModePreferIPv4:
		return DNSModeNamePreferIPv4
	case DNSModePreferIPv6:
		return DNSModeNamePreferIPv6
	case DNSModeIPv4Only:
		return DNSModeNameIPv4Only
	case DNSModeIPv6Only:
		return DNSModeNameIPv6Only
	case DNSModeMultiPreferIPv4:
		return DNSModeNameMultiPreferIPv4
	case DNSModeMultiPreferIPv6:
		return DNSModeNameMultiPreferIPv6
	case DNSModeMultiIPv4Only:
		return DNSModeNameMultiIPv4Only
	case DNSModeMultiIPv6Only:
		return DNSModeNameMultiIPv6Only
	}
	return "unknown"
}

func (m *DNSMode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case DNSModeNamePreferIPv4:
		*m = DNSModePreferIPv4
	case DNSModeNamePreferIPv6:
		*m = DNSModePreferIPv6
	case DNSModeNameIPv4Only:
		*m = DNSModeIPv4Only
	case DNSModeNameIPv6Only:
		*m = DNSModeIPv6Only
	case DNSModeNameMultiPreferIPv4:
		*m = DNSModeMultiPreferIPv4
	case DNSModeNameMultiPreferIPv6:
		*m = DNSModeMultiPreferIPv6
	case DNSModeNameMultiIPv4Only:
		*m = DNSModeMultiIPv4Only
	case DNSModeNameMultiIPv6Only:
		*m = DNSModeMultiIPv6Only
	default:
		return fmt.Errorf("invalid dns_mode: %q", s)
	}
	return nil
}

func pickFirstARecord(answer []dns.RR) net.IP {
	for _, ans := range answer {
		if record, ok := ans.(*dns.A); ok {
			return record.A
		}
	}
	return nil
}

func pickFirstAAAARecord(answer []dns.RR) net.IP {
	for _, ans := range answer {
		if record, ok := ans.(*dns.AAAA); ok {
			return record.AAAA
		}
	}
	return nil
}

func pickARecords(answer []dns.RR) []net.IP {
	ips := make([]net.IP, 0)
	for _, ans := range answer {
		if record, ok := ans.(*dns.A); ok {
			ips = append(ips, record.A)
		}
	}
	return ips
}

func pickAAAARecords(answer []dns.RR) []net.IP {
	ips := make([]net.IP, 0)
	for _, ans := range answer {
		if record, ok := ans.(*dns.AAAA); ok {
			ips = append(ips, record.AAAA)
		}
	}
	return ips
}

func (c *Core) dnsMsgSetQuestion(msg *dns.Msg, fqdn string, qtype uint16) {
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	if c.dns.qtype2 == 0 {
		msg.Question = []dns.Question{
			{
				Name:   fqdn,
				Qtype:  qtype,
				Qclass: dns.ClassINET,
			},
		}
	} else {
		msg.Question = []dns.Question{
			{
				Name:   fqdn,
				Qtype:  qtype,
				Qclass: dns.ClassINET,
			},
			{
				Name:   fqdn,
				Qtype:  c.dns.qtype2,
				Qclass: dns.ClassINET,
			},
		}
	}
}

func (c *Core) dnsResolveSingle(domain string, mode DNSMode, ans []dns.RR, msg *dns.Msg, err error) (ip net.IP, _ error) {
	switch mode {
	case DNSModeIPv4Only:
		if ip = pickFirstARecord(ans); ip == nil {
			return nil, E.New("A record not found")
		}
	case DNSModeIPv6Only:
		if ip = pickFirstAAAARecord(ans); ip == nil {
			return nil, E.New("AAAA record not found")
		}
	case DNSModePreferIPv4:
		if ip = pickFirstARecord(ans); ip == nil {
			c.dnsMsgSetQuestion(msg, domain, dns.TypeAAAA)
			resp, err2 := c.dns.exchange(msg)
			if err2 != nil {
				return nil, E.WithStr("dns exchange", E.Join(err, err2))
			}
			if resp.Rcode != dns.RcodeSuccess {
				return nil, E.New("bad rcode: " + dns.RcodeToString[resp.Rcode])
			}
			if ip = pickFirstAAAARecord(resp.Answer); ip == nil {
				return nil, E.New("record not found")
			}
		}
	case DNSModePreferIPv6:
		if ip = pickFirstAAAARecord(ans); ip == nil {
			c.dnsMsgSetQuestion(msg, domain, dns.TypeA)
			resp, err2 := c.dns.exchange(msg)
			if err2 != nil {
				return nil, E.WithStr("dns exchange", E.Join(err, err2))
			}
			if resp.Rcode != dns.RcodeSuccess {
				return nil, E.New("bad rcode: " + dns.RcodeToString[resp.Rcode])
			}
			if ip = pickFirstARecord(resp.Answer); ip == nil {
				return nil, E.New("record not found")
			}
		}
	}
	return
}

func (c *Core) dnsResolveMulti(domain string, mode DNSMode, ans []dns.RR, msg *dns.Msg, err error) (ips []net.IP, _ error) {
	switch mode {
	case DNSModeMultiIPv4Only:
		if ips = pickARecords(ans); ips == nil {
			return nil, E.New("A record not found")
		}
	case DNSModeMultiIPv6Only:
		if ips = pickAAAARecords(ans); ips == nil {
			return nil, E.New("AAAA record not found")
		}
	case DNSModeMultiPreferIPv4:
		if ips = pickARecords(ans); ips == nil {
			c.dnsMsgSetQuestion(msg, domain, dns.TypeAAAA)
			resp, err2 := c.dns.exchange(msg)
			if err2 != nil {
				return nil, E.WithStr("dns exchange", E.Join(err, err2))
			}
			if resp.Rcode != dns.RcodeSuccess {
				return nil, E.New("bad rcode: " + dns.RcodeToString[resp.Rcode])
			}
			if ips = pickAAAARecords(resp.Answer); ips == nil {
				return nil, E.New("record not found")
			}
		}
	case DNSModeMultiPreferIPv6:
		if ips = pickAAAARecords(ans); ips == nil {
			c.dnsMsgSetQuestion(msg, domain, dns.TypeA)
			resp, err2 := c.dns.exchange(msg)
			if err2 != nil {
				return nil, E.WithStr("dns exchange", E.Join(err, err2))
			}
			if resp.Rcode != dns.RcodeSuccess {
				return nil, E.New("bad rcode: " + dns.RcodeToString[resp.Rcode])
			}
			if ips = pickARecords(resp.Answer); ips == nil {
				return nil, E.New("record not found")
			}
		}
	}
	return
}

func (c *Core) doDNSResolve(domain string, mode DNSMode, cacheTTL time.Duration) (*dial.Dst, error) {
	msg := new(dns.Msg)
	fqdn := dns.Fqdn(domain)
	switch mode {
	case DNSModePreferIPv4, DNSModeIPv4Only, DNSModeMultiPreferIPv4, DNSModeMultiIPv4Only:
		c.dnsMsgSetQuestion(msg, fqdn, dns.TypeA)
	case DNSModePreferIPv6, DNSModeIPv6Only, DNSModeMultiPreferIPv6, DNSModeMultiIPv6Only:
		c.dnsMsgSetQuestion(msg, fqdn, dns.TypeAAAA)
	}
	if c.dns.edns0SubnetOpt != nil {
		msg.Extra = []dns.RR{c.dns.edns0SubnetOpt}
	}

	resp, err := c.dns.exchange(msg)
	if err != nil {
		return nil, E.WithStr("dns exchange", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, E.New("bad rcode: " + dns.RcodeToString[resp.Rcode])
	}

	var dst *dial.Dst
	switch mode {
	case DNSModeIPv4Only, DNSModeIPv6Only, DNSModePreferIPv4, DNSModePreferIPv6:
		ip, err := c.dnsResolveSingle(fqdn, mode, resp.Answer, msg, err)
		if err != nil {
			return nil, err
		}
		dst = dial.NewSingleDst(ip.String())
	case DNSModeMultiIPv4Only, DNSModeMultiIPv6Only, DNSModeMultiPreferIPv4, DNSModeMultiPreferIPv6:
		ips, err := c.dnsResolveMulti(fqdn, mode, resp.Answer, msg, err)
		if err != nil {
			return nil, err
		}
		dst = dial.NewDstFromIPs(ips)
	}

	if cacheTTL != 0 && cacheTTL != unsetInt && c.dns.cache != nil {
		c.dns.cache.AddWithLifetime(domain, dst, cacheTTL)
	}
	return dst, nil
}

func (c *Core) dnsResolve(domain string, mode DNSMode, cacheTTL time.Duration) (dst *dial.Dst, cached bool, err error) {
	if c.dns.cache != nil {
		if dst, ok := c.dns.cache.Get(domain); ok {
			return dst, true, nil
		}
	}

	if c.dns.resolveGroup == nil {
		dst, err = c.doDNSResolve(domain, mode, cacheTTL)
	} else {
		dst, err, _ = c.dns.resolveGroup.Do(domain, func() (*dial.Dst, error) {
			return c.doDNSResolve(domain, mode, cacheTTL)
		})
	}

	return
}

// Modified from github.com/miekg/dns.Client
type antiHijackDNSClient struct {
	dns.Client
	waitTimeout, minRTT time.Duration
}

const dnsRWTimeout = 2 * time.Second

func (c *antiHijackDNSClient) readTimeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	if c.ReadTimeout != 0 {
		return c.ReadTimeout
	}
	return dnsRWTimeout
}

func (c *antiHijackDNSClient) writeTimeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	if c.WriteTimeout != 0 {
		return c.WriteTimeout
	}
	return dnsRWTimeout
}

func (c *antiHijackDNSClient) getTimeoutForRequest(timeout time.Duration) time.Duration {
	var requestTimeout time.Duration
	if c.Timeout != 0 {
		requestTimeout = c.Timeout
	} else {
		requestTimeout = timeout
	}
	if c.Dialer != nil && c.Dialer.Timeout != 0 {
		if c.Dialer.Timeout < requestTimeout {
			requestTimeout = c.Dialer.Timeout
		}
	}
	return requestTimeout
}

func (c *antiHijackDNSClient) Exchange(m *dns.Msg, address string) (r *dns.Msg, rtt time.Duration, err error) {
	co, err := c.Dial(address)
	if err != nil {
		return nil, 0, err
	}
	defer co.Close()
	return c.ExchangeWithConn(m, co)
}

func (c *antiHijackDNSClient) ExchangeWithConn(m *dns.Msg, conn *dns.Conn) (r *dns.Msg, rtt time.Duration, err error) {
	return c.ExchangeWithConnContext(context.Background(), m, conn)
}

func (c *antiHijackDNSClient) ExchangeWithConnContext(ctx context.Context, m *dns.Msg, co *dns.Conn) (r *dns.Msg, rtt time.Duration, err error) {
	opt := m.IsEdns0()
	if opt != nil && opt.UDPSize() >= dns.MinMsgSize {
		co.UDPSize = opt.UDPSize()
	}
	if opt == nil && c.UDPSize >= dns.MinMsgSize {
		co.UDPSize = c.UDPSize
	}

	t := time.Now()
	writeDeadline := t.Add(c.getTimeoutForRequest(c.writeTimeout()))
	readDeadline := t.Add(c.getTimeoutForRequest(c.readTimeout()))

	if deadline, ok := ctx.Deadline(); ok && !deadline.IsZero() {
		if deadline.Before(writeDeadline) {
			writeDeadline = deadline
		}
		if deadline.Before(readDeadline) {
			readDeadline = deadline
		}
	}
	co.SetWriteDeadline(writeDeadline)

	if c.waitTimeout != 0 {
		if waitDeadline := t.Add(c.waitTimeout); waitDeadline.Before(readDeadline) {
			readDeadline = waitDeadline
		}
	}
	co.SetReadDeadline(readDeadline)

	co.TsigSecret, co.TsigProvider = c.TsigSecret, c.TsigProvider

	if err = co.WriteMsg(m); err != nil {
		return nil, 0, err
	}

	var (
		bestR           *dns.Msg
		bestRecordCount int
		bestRTT         time.Duration
		lastErr         error
	)

	for {
		r, err = co.ReadMsg()
		curRTT := time.Since(t)

		if err != nil {
			lastErr = err
			break
		}

		if c.minRTT != 0 && curRTT < c.minRTT {
			continue
		}

		if r.Id == m.Id {
			if c.waitTimeout <= 0 || (hasEDNS0Subnet(m) && hasEDNS0Subnet(r)) {
				return r, curRTT, nil
			}

			recordCount := len(r.Answer) + len(r.Ns) + len(r.Extra)
			if recordCount >= bestRecordCount {
				bestR = r
				bestRecordCount = recordCount
				bestRTT = curRTT
			}
		}

		if c.waitTimeout > 0 && curRTT >= c.waitTimeout {
			break
		}
	}

	if bestR != nil {
		return bestR, bestRTT, nil
	}

	return r, time.Since(t), lastErr
}

func hasEDNS0Subnet(resp *dns.Msg) bool {
	for _, rr := range resp.Extra {
		opt, ok := rr.(*dns.OPT)
		if !ok {
			continue
		}
		for _, o := range opt.Option {
			if o.Option() == dns.EDNS0SUBNET {
				return true
			}
		}
	}
	return false
}

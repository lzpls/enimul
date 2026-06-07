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

	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/freelru"
	"github.com/lzpls/enimul/internal/singleflight"
	"golang.org/x/net/proxy"

	"github.com/miekg/dns"
)

var (
	dnsAddr         string
	dnsClient       DNSClient
	httpClient      *http.Client
	dnsExchange     func(req *dns.Msg) (resp *dns.Msg, err error)
	dnsCache        *freelru.ShardedLRU[string, string]
	dnsCacheTTL     time.Duration
	dnsSingleflight *singleflight.Group[string, string]
	edns0SubnetOpt  *dns.OPT
)

type DNSClient interface {
	Exchange(*dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type DNSConfig struct {
	Type          string `json:"type"`
	Addr          string `json:"addr"`
	SingleFlight  bool   `json:"singleflight"`
	CacheTTL      int    `json:"cache_ttl"`
	CacheCapacity uint32 `json:"cache_cap"`
	EDNS0Subnet   string `json:"edns0_subnet"`

	UDPSize     uint16 `json:"udp_size"`
	WaitTimeout string `json:"wait_timeout"`

	DoHSocks5Addr string `json:"doh_socks5_addr"`
}

func setDNS(c DNSConfig) error {
	if c.Addr == "" {
		return E.New("dns.addr cannot be empty")
	}
	if _, err := netip.ParseAddrPort(c.Addr); err != nil {
		return E.WithStr("invalid dns.addr", err)
	}

	dnsAddr = c.Addr
	switch c.Type {
	case "", "udp": // default
		cli := dns.Client{}
		if c.UDPSize > 0 {
			cli.UDPSize = c.UDPSize
		}
		if c.WaitTimeout == "" {
			dnsClient = &cli
		} else {
			timeout, err := time.ParseDuration(c.WaitTimeout)
			if err != nil {
				return E.WithStr("invalid dns.wait_timeout", err)
			}
			if timeout < 0 {
				return E.New("dns.wait_timeout must be greater than 0")
			}
			dnsClient = &antiHijackDNSClient{
				Client:      cli,
				waitTimeout: timeout,
			}
		}
		dnsExchange = dnsClientExchange
	case "tcp":
		dnsClient = &dns.Client{Net: "tcp"}
		dnsExchange = dnsClientExchange
	case "tls":
		dnsClient = &dns.Client{Net: "tcp-tls"}
		dnsExchange = dnsClientExchange
	case "https":
		if !isValidHTTPSURL(dnsAddr) {
			return E.NewAny("invalid DoH URL: ", dnsAddr)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if c.DoHSocks5Addr == "" {
			var err error
			transport.DialContext, err = genDoHDialFunc()
			if err != nil {
				return E.WithStr("generate DoH dial function", err)
			}
		} else {
			dialer, err := proxy.SOCKS5("tcp", c.DoHSocks5Addr, nil, proxy.Direct)
			if err != nil {
				return E.WithStr("create socks5 dialer", err)
			}
			transport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
		httpClient = &http.Client{Transport: transport}
		dnsExchange = dohExchange
	}

	if c.SingleFlight {
		dnsSingleflight = new(singleflight.Group[string, string])
	}

	if c.CacheTTL < 0 {
		return E.NewAny("invalid dns.cache_ttl: ", c.CacheTTL)
	}
	if c.CacheTTL != 0 {
		if c.CacheCapacity == 0 {
			c.CacheCapacity = 4096
		}
		var err error
		dnsCache, err = freelru.NewSharded[string, string](c.CacheCapacity, hashStringXXHASH)
		if err != nil {
			return E.WithStr("init DNS cache", err)
		}
		dnsCacheTTL = time.Duration(c.CacheTTL) * time.Second
	}

	if c.EDNS0Subnet != "" {
		prefix, err := netip.ParsePrefix(c.EDNS0Subnet)
		if err != nil {
			return fmt.Errorf("invalid edns0_subnet %s: %w", c.EDNS0Subnet, err)
		}
		family := uint16(1)
		if prefix.Addr().Is6() {
			family = 2
		}
		edns0 := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        family,
			SourceNetmask: uint8(prefix.Bits()),
			Address:       prefix.Addr().AsSlice(),
		}
		edns0SubnetOpt = &dns.OPT{
			Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
			Option: []dns.EDNS0{edns0},
		}
	}

	return nil
}

func isValidHTTPSURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

type DNSMode uint8

const (
	DNSModeUnset DNSMode = iota
	DNSModePreferIPv4
	DNSModePreferIPv6
	DNSModeIPv4Only
	DNSModeIPv6Only
	DNSModeDefault = DNSModePreferIPv4
)

const (
	DNSModeNamePreferIPv4 = "prefer_ipv4"
	DNSModeNamePreferIPv6 = "prefer_ipv6"
	DNSModeNameIPv4Only   = "ipv4_only"
	DNSModeNameIPv6Only   = "ipv6_only"
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
	default:
		return E.New("invalid dns_mode: " + s)
	}
	return nil
}

func dnsClientExchange(req *dns.Msg) (resp *dns.Msg, err error) {
	resp, _, err = dnsClient.Exchange(req, dnsAddr)
	return resp, err
}

func dohExchange(req *dns.Msg) (resp *dns.Msg, err error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, E.WithStr("pack dns request", err)
	}
	url := dnsAddr + "?dns=" + base64.RawURLEncoding.EncodeToString(wire)
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
	resp = new(dns.Msg)
	if err = resp.Unpack(respWire); err != nil {
		return nil, E.WithStr("unpack dns response", err)
	}
	return
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

func doDNSResolve(domain string, dnsMode DNSMode) (string, error) {
	msg := new(dns.Msg)
	switch dnsMode {
	case DNSModePreferIPv4, DNSModeIPv4Only:
		msg.SetQuestion(domain+".", dns.TypeA)
	case DNSModePreferIPv6, DNSModeIPv6Only:
		msg.SetQuestion(domain+".", dns.TypeAAAA)
	}
	if edns0SubnetOpt != nil {
		msg.Extra = []dns.RR{edns0SubnetOpt}
	}

	resp, err := dnsExchange(msg)
	if err != nil {
		return "", E.WithStr("dns exchange", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", E.New("bad rcode: " + dns.RcodeToString[resp.Rcode])
	}

	var ip net.IP
	switch dnsMode {
	case DNSModeIPv4Only:
		if ip = pickFirstARecord(resp.Answer); ip == nil {
			return "", E.New("A record not found")
		}
	case DNSModeIPv6Only:
		if ip = pickFirstAAAARecord(resp.Answer); ip == nil {
			return "", E.New("AAAA record not found")
		}
	case DNSModePreferIPv4:
		if ip = pickFirstARecord(resp.Answer); ip == nil {
			msg.SetQuestion(domain+".", dns.TypeAAAA)
			resp, err2 := dnsExchange(msg)
			if err2 != nil {
				return "", E.WithStr("dns exchange", E.Join(err, err2))
			}
			if resp.Rcode != dns.RcodeSuccess {
				return "", E.New("bad rcode: " + dns.RcodeToString[resp.Rcode])
			}
			if ip = pickFirstAAAARecord(resp.Answer); ip == nil {
				return "", E.New("record not found")
			}
		}
	case DNSModePreferIPv6:
		if ip = pickFirstAAAARecord(resp.Answer); ip == nil {
			msg.SetQuestion(domain+".", dns.TypeA)
			resp, err2 := dnsExchange(msg)
			if err2 != nil {
				return "", E.WithStr("dns exchange", E.Join(err, err2))
			}
			if resp.Rcode != dns.RcodeSuccess {
				return "", E.New("bad rcode: " + dns.RcodeToString[resp.Rcode])
			}
			if ip = pickFirstARecord(resp.Answer); ip == nil {
				return "", E.New("record not found")
			}
		}
	}

	ipStr := ip.String()
	if dnsCache != nil {
		dnsCache.AddWithLifetime(domain, ipStr, dnsCacheTTL)
	}
	return ipStr, nil
}

func dnsResolve(domain string, dnsMode DNSMode) (ip string, cached bool, err error) {
	if dnsCache != nil {
		if ip, ok := dnsCache.Get(domain); ok {
			return ip, true, nil
		}
	}

	if dnsSingleflight == nil {
		ip, err = doDNSResolve(domain, dnsMode)
	} else {
		ip, err, _ = dnsSingleflight.Do(domain, func() (string, error) {
			return doDNSResolve(domain, dnsMode)
		})
	}

	return
}

// Modified from github.com/miekg/dns.Client
type antiHijackDNSClient struct {
	dns.Client
	waitTimeout time.Duration
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

	if waitDeadline := t.Add(c.waitTimeout); readDeadline.Before(waitDeadline) {
		readDeadline = waitDeadline
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

		if r.Id == m.Id {
			if edns0SubnetOpt != nil && hasEDNS0Subnet(r) {
				return r, curRTT, nil
			}

			recordCount := len(r.Answer) + len(r.Ns) + len(r.Extra)
			if recordCount >= bestRecordCount {
				bestR = r
				bestRecordCount = recordCount
				bestRTT = curRTT
			}
		}

		if curRTT >= c.waitTimeout {
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

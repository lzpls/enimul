package core

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/freelru"
	"github.com/lzpls/enimul/internal/singleflight"

	"github.com/miekg/dns"
)

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

var (
	dnsAddr         string
	dnsClient       *dns.Client
	httpClient      *http.Client
	dnsExchange     func(req *dns.Msg) (resp *dns.Msg, err error)
	dnsCache        *freelru.ShardedLRU[string, string]
	dnsCacheTTL     time.Duration
	dnsSingleflight *singleflight.Group[string, string]
)

func do53Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
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
		ip = pickFirstARecord(resp.Answer)
		if ip == nil {
			return "", E.New("A record not found")
		}
	case DNSModeIPv6Only:
		ip = pickFirstAAAARecord(resp.Answer)
		if ip == nil {
			return "", E.New("AAAA record not found")
		}
	case DNSModePreferIPv4:
		ip = pickFirstARecord(resp.Answer)
		if ip == nil {
			msg.SetQuestion(domain+".", dns.TypeAAAA)
			resp, err2 := dnsExchange(msg)
			if err2 != nil {
				return "", E.WithStr("dns exchange", E.Join(err, err2))
			}
			if resp.Rcode != dns.RcodeSuccess {
				return "", E.New("bad rcode: " + dns.RcodeToString[resp.Rcode])
			}
			ip = pickFirstAAAARecord(resp.Answer)
			if ip == nil {
				return "", E.New("record not found")
			}
		}
	case DNSModePreferIPv6:
		ip = pickFirstAAAARecord(resp.Answer)
		if ip == nil {
			msg.SetQuestion(domain+".", dns.TypeA)
			resp, err2 := dnsExchange(msg)
			if err2 != nil {
				return "", E.WithStr("dns exchange", E.Join(err, err2))
			}
			if resp.Rcode != dns.RcodeSuccess {
				return "", E.New("bad rcode: " + dns.RcodeToString[resp.Rcode])
			}
			ip = pickFirstARecord(resp.Answer)
			if ip == nil {
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

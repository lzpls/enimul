package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lzpls/enimul/internal/addrtrie"
	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/freelru"
	"github.com/lzpls/enimul/internal/log"
	"github.com/lzpls/enimul/internal/singleflight"

	"github.com/cespare/xxhash/v2"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

type Config struct {
	LogLevel         log.Level          `json:"log_level"`
	LogOutput        string             `json:"log_output"`
	Socks5Addr       string             `json:"socks5_address"`
	HttpAddr         string             `json:"http_address"`
	OutboundBinding  dial.BindingOption `json:"outbound_binding"`
	DNSAddr          string             `json:"dns_addr"`
	UDPSize          uint16             `json:"udp_minsize"`
	DoHProxy         string             `json:"socks5_for_doh"`
	FakeTTLRules     string             `json:"fake_ttl_rules"`
	DNSSingleflight  bool               `json:"dns_singleflight"`
	DNSCacheTTL      int                `json:"dns_cache_ttl"`
	DNSCacheCapacity uint32             `json:"dns_cache_cap"`
	TTLSingleflight  bool               `json:"ttl_singleflight"`
	TTLCacheTTL      int                `json:"ttl_cache_ttl"`
	TTLCacheCapacity uint32             `json:"ttl_cache_cap"`
	IPPools          map[string]*IPPool `json:"ip_pools"`
	Hosts            map[string]string  `json:"hosts"`
	DefaultPolicy    Policy             `json:"default_policy"`
	DomainPolicies   map[string]Policy  `json:"domain_policies"`
	IpPolicies       map[string]Policy  `json:"ip_policies"`
}

func LoadConfig(filePath string) (string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	var conf Config
	if err = json.NewDecoder(file).Decode(&conf); err != nil {
		file.Close()
		return "", "", err
	}
	file.Close()

	if err := dial.SetLocalAddr(conf.OutboundBinding); err != nil {
		return "", "", err
	}

	logLevel = conf.LogLevel
	if err := setLogOutput(conf.LogOutput); err != nil {
		return "", "", err
	}

	if len(conf.IPPools) > 0 {
		ipPools = conf.IPPools
		for tag, pool := range ipPools {
			if err := pool.Init(newLogger("P[" + tag + "]")); err != nil {
				return "", "", E.WithStr("init ip pool "+tag, err)
			}
		}
	}

	if conf.DNSSingleflight {
		dnsSingleflight = new(singleflight.Group[string, string])
	}
	if conf.TTLSingleflight {
		ttlSingleflight = new(singleflight.Group[string, int])
	}

	if conf.DNSCacheTTL < 0 {
		return "", "", fmt.Errorf("invalid dns_cache_ttl: %d", conf.DNSCacheTTL)
	}
	if conf.DNSCacheTTL != 0 {
		if conf.DNSCacheCapacity == 0 {
			conf.DNSCacheCapacity = 4096
		}
		dnsCache, err = freelru.NewSharded[string, string](conf.DNSCacheCapacity, hashStringXXHASH)
		if err != nil {
			return "", "", E.WithStr("init dns cache", err)
		}
		dnsCacheTTL = time.Duration(conf.DNSCacheTTL) * time.Second
	}

	if conf.TTLCacheTTL < 0 {
		return "", "", fmt.Errorf("invalid ttl_cache_ttl: %d", conf.TTLCacheTTL)
	}
	if conf.TTLCacheTTL != 0 {
		if conf.TTLCacheCapacity == 0 {
			conf.TTLCacheCapacity = 1024
		}
		ttlCache, err = freelru.NewSharded[string, int](conf.TTLCacheCapacity, hashStringXXHASH)
		if err != nil {
			return "", "", E.WithStr("init TTL cache", err)
		}
		ttlCacheTTL = time.Duration(conf.TTLCacheTTL) * time.Second
	}

	if conf.FakeTTLRules != "" {
		if err = loadTTLRules(conf.FakeTTLRules); err != nil {
			return "", "", E.WithStr("load fake TTL rules", err)
		}
	}

	defaultPolicy = conf.DefaultPolicy

	hostsMatcher = addrtrie.NewDomainMatcher[string]()
	for patterns, host := range conf.Hosts {
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, pattern := range expandPattern(elem) {
				hostsMatcher.Add(pattern, host)
			}
		}
	}

	domainMatcher = addrtrie.NewDomainMatcher[*Policy]()
	for patterns, policy := range conf.DomainPolicies {
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, pattern := range expandPattern(elem) {
				domainMatcher.Add(pattern, &policy)
			}
		}
	}

	ipMatcher = addrtrie.NewIPv4Trie[*Policy]()
	ipv6Matcher = addrtrie.NewIPv6Trie[*Policy]()
	for patterns, policy := range conf.IpPolicies {
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, ipOrNet := range expandPattern(elem) {
				if isIPv6(ipOrNet) {
					ipv6Matcher.Insert(ipOrNet, &policy)
				} else {
					ipMatcher.Insert(ipOrNet, &policy)
				}
			}
		}
	}

	dnsAddr = conf.DNSAddr
	if strings.HasPrefix(dnsAddr, "https://") {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if conf.DoHProxy == "" {
			transport.DialContext, err = genDoHDialFunc()
			if err != nil {
				return "", "", err
			}
		} else {
			dialer, err := proxy.SOCKS5("tcp", conf.DoHProxy, nil, proxy.Direct)
			if err != nil {
				return "", "", E.WithStr("create socks5 dialer", err)
			}
			transport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
		httpClient = &http.Client{Transport: transport}
		dnsExchange = dohExchange
	} else {
		dnsExchange = do53Exchange
		dnsClient = new(dns.Client)
		if conf.UDPSize > 0 {
			dnsClient.UDPSize = conf.UDPSize
		}
	}

	return conf.Socks5Addr, conf.HttpAddr, nil
}

// for freelru
func hashStringXXHASH(s string) uint32 {
	return uint32(xxhash.Sum64String(s))
}

func expandPattern(s string) []string {
	left := -1
	for i, ch := range s {
		if ch == '(' {
			left = i
			break
		}
	}

	if left == -1 {
		return splitByPipe(s)
	}

	right := -1
	depth := 1
	for i := left + 1; i < len(s); i++ {
		if s[i] == '(' {
			depth++
		} else if s[i] == ')' {
			depth--
			if depth == 0 {
				right = i
				break
			}
		}
	}

	if right == -1 {
		return splitByPipe(s)
	}

	prefix := s[:left]
	inner := s[left+1 : right]
	suffix := s[right+1:]

	parts := splitByPipe(inner)

	suffixResults := expandPattern(suffix)

	result := make([]string, 0, len(parts)*len(suffixResults))
	for _, part := range parts {
		for _, suff := range suffixResults {
			result = append(result, prefix+part+suff)
		}
	}

	return result
}

func splitByPipe(s string) []string {
	if s == "" {
		return []string{""}
	}
	result := []string{}
	curr := ""
	for _, ch := range s {
		if ch == '|' {
			result = append(result, curr)
			curr = ""
		} else {
			curr += string(ch)
		}
	}
	result = append(result, curr)
	return result
}

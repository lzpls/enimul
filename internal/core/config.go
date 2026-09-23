package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/lzpls/enimul/internal/addrtrie"
	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/jsonc"
	"github.com/lzpls/enimul/internal/log"
	"github.com/lzpls/enimul/internal/orderedmap"
)

type Config struct {
	LogLevel         log.Level                `json:"log_level"`
	LogOutput        string                   `json:"log_output"`
	Socks5Addr       string                   `json:"socks5_address"`
	HttpAddr         string                   `json:"http_address"`
	SNIProxyAddr     string                   `json:"sniproxy_address"`
	OutboundBinding  dial.BindingOption       `json:"outbound_binding"`
	DNSConfig        DNSConfig                `json:"dns"`
	TTLProbingConfig TTLProbingConfig         `json:"ttl_probing"`
	IPPools          map[string]*IPPool       `json:"ip_pools"`
	Hosts            orderedmap.Map[dial.Dst] `json:"hosts"`
	DefaultPolicy    Policy                   `json:"default_policy"`
	DomainPolicies   orderedmap.Map[Policy]   `json:"domain_policies"`
	IpPolicies       orderedmap.Map[Policy]   `json:"ip_policies"`
}

func (c *Core) LoadConfig(filePath string, disallowUnknownFields bool) (string, string, string, error) {
	anErr := func(text string, err error) (string, string, string, error) {
		return "", "", "", E.WithStr(text, err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return anErr("read config", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(jsonc.ToJSONInPlace(data)))
	if disallowUnknownFields {
		decoder.DisallowUnknownFields()
	}
	var conf Config
	if err = decoder.Decode(&conf); err != nil {
		return anErr("decode config", err)
	}

	if err = c.setLogOutput(conf.LogOutput); err != nil {
		return anErr("set log output", err)
	}
	c.logLevel = conf.LogLevel

	c.dialer, err = dial.NewDialer(c.newLogger("[dial]"), conf.OutboundBinding)
	if err != nil {
		return anErr("create dialer", err)
	}

	if len(conf.IPPools) > 0 {
		c.ipPools = conf.IPPools
		for tag, pool := range c.ipPools {
			pool.Init(c.newLogger("P["+tag+"]"), c.dialer)
		}
	}

	c.defaultPolicy = conf.DefaultPolicy

	c.hostsMatcher = addrtrie.NewDomainMatcher[*dial.Dst]()
	for patterns, host := range conf.Hosts.All() {
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, pattern := range expandPattern(elem) {
				c.hostsMatcher.Add(pattern, &host)
			}
		}
	}

	c.domainMatcher = addrtrie.NewDomainMatcher[*Policy]()
	for patterns, policy := range conf.DomainPolicies.All() {
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, pattern := range expandPattern(elem) {
				c.domainMatcher.Add(pattern, &policy)
			}
		}
	}

	c.ipv4Matcher = addrtrie.NewIPv4Trie[*Policy]()
	c.ipv6Matcher = addrtrie.NewIPv6Trie[*Policy]()
	for patterns, policy := range conf.IpPolicies.All() {
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, s := range expandPattern(elem) {
				if strings.Contains(s, ":") {
					err = c.ipv6Matcher.Insert(s, &policy)
				} else {
					err = c.ipv4Matcher.Insert(s, &policy)
				}
				if err != nil {
					return "", "", "", fmt.Errorf("invalid ip/cidr %q in %q: %w", s, patterns, err)
				}
			}
		}
	}

	if err = c.setDNS(conf.DNSConfig); err != nil {
		return anErr("init dns", err)
	}

	if err = c.setTTLProbing(conf.TTLProbingConfig); err != nil {
		return anErr("init ttl probing", err)
	}

	return conf.Socks5Addr, conf.HttpAddr, conf.SNIProxyAddr, nil
}

func expandPattern(s string) []string {
	const (
		start = '('
		end   = ')'
		sep   = "|"
	)

	left := strings.IndexByte(s, start)
	if left == -1 {
		return strings.Split(s, sep)
	}
	right := strings.IndexByte(s, end)
	if right == -1 {
		return strings.Split(s, sep)
	}

	prefix := s[:left]
	inner := s[left+1 : right]
	suffix := s[right+1:]

	parts := strings.Split(inner, sep)
	suffixResults := expandPattern(suffix)

	result := make([]string, len(parts)*len(suffixResults))
	i := 0
	for _, part := range parts {
		for _, suff := range suffixResults {
			result[i] = prefix + part + suff
			i++
		}
	}

	return result
}

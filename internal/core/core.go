package core

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lzpls/enimul/internal/addrtrie"
	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/log"
	"github.com/lzpls/enimul/internal/orderedmap"
)

const Version = "v0.7.0-alpha.3"

const maxConnID = 0xfffff

type inboundAddrs struct{ socks5, http, sniProxy string }

func inboundIsEnabled(addr string) bool { return addr != "" && addr != "none" }

type Core struct {
	logLevel       log.Level
	logOutput      io.Writer
	inboundAddrs   *inboundAddrs
	dialer         *dial.Dialer
	dns            dnsFields
	ttl            ttlProbingFields
	ipPools        map[string]*IPPool
	defaultPolicy  *Policy
	hosts          *addrtrie.DomainMatcher[*dial.Dst]
	domainPolicies *addrtrie.DomainMatcher[*Policy]
	ipv4Policies   *addrtrie.IPv4Trie[*Policy]
	ipv6Policies   *addrtrie.IPv6Trie[*Policy]
	httpConnID     atomic.Uint32
}

func (c *Core) Serve() (<-chan struct{}, bool) {
	var wg sync.WaitGroup
	n := 0
	if addr := c.inboundAddrs.socks5; inboundIsEnabled(addr) {
		n++
		wg.Go(func() { c.serveSOCKS5(addr) })
	}
	if addr := c.inboundAddrs.http; inboundIsEnabled(addr) {
		n++
		wg.Go(func() { c.serveHTTPProxy(addr) })
	}
	if addr := c.inboundAddrs.sniProxy; inboundIsEnabled(addr) {
		n++
		wg.Go(func() { c.serveSNIProxy(addr) })
	}
	if n == 0 {
		return nil, false
	}
	c.inboundAddrs = nil
	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()
	return done, true
}

type Config struct {
	LogLevel         log.Level                     `json:"log_level"`
	LogOutput        *string                       `json:"log_output"`
	Socks5Addr       *string                       `json:"socks5_address"`
	HttpAddr         *string                       `json:"http_address"`
	SNIProxyAddr     *string                       `json:"sniproxy_address"`
	OutboundBinding  *dial.BindingOption           `json:"outbound_binding"`
	DNSConfig        *DNSConfig                    `json:"dns"`
	TTLProbingConfig *TTLProbingConfig             `json:"ttl_probing"`
	IPPools          map[string]IPPoolOptions      `json:"ip_pools"`
	Hosts            orderedmap.Map[dial.Dst]      `json:"hosts"`
	DefaultPolicy    *PolicyOptions                `json:"default_policy"`
	DomainPolicies   orderedmap.Map[PolicyOptions] `json:"domain_policies"`
	IpPolicies       orderedmap.Map[PolicyOptions] `json:"ip_policies"`
}

type Builder struct {
	logLevel         log.Level
	logOutput        *string
	socks5Addr       *string
	httpAddr         *string
	sniProxyAddr     *string
	outboundBinding  *dial.BindingOption
	dnsConfig        *DNSConfig
	ttlProbingConfig *TTLProbingConfig
	ipPools          map[string]IPPoolOptions
	hosts            *addrtrie.DomainMatcher[*dial.Dst]
	defaultPolicy    *Policy
	domainPolicies   *addrtrie.DomainMatcher[*Policy]
	ipv4Policies     *addrtrie.IPv4Trie[*Policy]
	ipv6Policies     *addrtrie.IPv6Trie[*Policy]
}

func NewBuilder() *Builder {
	emptyStr := new(string)
	var defaultPolicy Policy
	defaultPolicy.init()
	return &Builder{
		logLevel:         log.LevelInfo,
		logOutput:        emptyStr,
		socks5Addr:       emptyStr,
		httpAddr:         emptyStr,
		sniProxyAddr:     emptyStr,
		outboundBinding:  new(dial.BindingOption),
		dnsConfig:        new(DNSConfig),
		ttlProbingConfig: new(TTLProbingConfig),
		hosts:            addrtrie.NewDomainMatcher[*dial.Dst](),
		defaultPolicy:    &defaultPolicy,
		domainPolicies:   addrtrie.NewDomainMatcher[*Policy](),
		ipv4Policies:     addrtrie.NewIPv4Trie[*Policy](),
		ipv6Policies:     addrtrie.NewIPv6Trie[*Policy](),
	}
}

func (b *Builder) Merge(cfg *Config) error {
	if len(b.ipPools) > 0 {
		for tag, options := range cfg.IPPools {
			if _, ok := b.ipPools[tag]; ok {
				return fmt.Errorf("duplicate ip pool tag %q", tag)
			}
			b.ipPools[tag] = options
		}
	} else if len(cfg.IPPools) > 0 {
		b.ipPools = cfg.IPPools
	}

	if cfg.DefaultPolicy != nil {
		policy, err := newPolicy(cfg.DefaultPolicy)
		if err != nil {
			return E.WithStr("invalid default_policy", err)
		}
		b.defaultPolicy = policy
	}

	for patterns, options := range cfg.DomainPolicies.All() {
		policy, err := newPolicy(&options)
		if err != nil {
			return fmt.Errorf("invalid policy for %q: %w", patterns, err)
		}
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, pattern := range expandPattern(elem) {
				b.domainPolicies.Add(pattern, policy)
			}
		}
	}

	for patterns, options := range cfg.IpPolicies.All() {
		policy, err := newPolicy(&options)
		if err != nil {
			return fmt.Errorf("invalid policy for %q: %w", patterns, err)
		}
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, s := range expandPattern(elem) {
				if strings.Contains(s, ":") {
					err = b.ipv6Policies.Insert(s, policy)
				} else {
					err = b.ipv4Policies.Insert(s, policy)
				}
				if err != nil {
					return fmt.Errorf("invalid ip/cidr %q in %q: %w", s, patterns, err)
				}
			}
		}
	}

	for patterns, host := range cfg.Hosts.All() {
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, pattern := range expandPattern(elem) {
				b.hosts.Add(pattern, &host)
			}
		}
	}

	if cfg.LogLevel != log.LevelUnset {
		b.logLevel = cfg.LogLevel
	}
	if cfg.LogOutput != nil {
		b.logOutput = cfg.LogOutput
	}
	if cfg.Socks5Addr != nil {
		b.socks5Addr = cfg.Socks5Addr
	}
	if cfg.HttpAddr != nil {
		b.httpAddr = cfg.HttpAddr
	}
	if cfg.SNIProxyAddr != nil {
		b.sniProxyAddr = cfg.SNIProxyAddr
	}
	if cfg.OutboundBinding != nil {
		b.outboundBinding = cfg.OutboundBinding
	}
	if cfg.DNSConfig != nil {
		b.dnsConfig = cfg.DNSConfig
	}
	if cfg.TTLProbingConfig != nil {
		b.ttlProbingConfig = cfg.TTLProbingConfig
	}
	return nil
}

func (b *Builder) Build() (*Core, error) {
	c := &Core{
		logLevel: b.logLevel,
		inboundAddrs: &inboundAddrs{
			socks5:   *b.socks5Addr,
			http:     *b.httpAddr,
			sniProxy: *b.sniProxyAddr,
		},
		hosts:          b.hosts,
		defaultPolicy:  b.defaultPolicy,
		domainPolicies: b.domainPolicies,
		ipv4Policies:   b.ipv4Policies,
		ipv6Policies:   b.ipv6Policies,
	}
	var err error

	if err := c.setLogOutput(*b.logOutput); err != nil {
		return nil, E.WithStr("set log output", err)
	}

	c.dialer, err = dial.NewDialer(c.newLogger("[dial]"), b.outboundBinding)
	if err != nil {
		return nil, E.WithStr("create dialer", err)
	}

	if l := len(b.ipPools); l > 0 {
		c.ipPools = make(map[string]*IPPool, l)
		for tag, options := range b.ipPools {
			pool, err := newIPPool(&options, c.newLogger("P["+tag+"]"), c.dialer)
			if err != nil {
				return nil, fmt.Errorf("create ip pool %q: %w", tag, err)
			}
			c.ipPools[tag] = pool
		}
		for _, pool := range c.ipPools {
			pool.Start()
		}
	}

	if err = c.setDNS(b.dnsConfig); err != nil {
		return nil, E.WithStr("init dns", err)
	}

	if err = c.setTTLProbing(b.ttlProbingConfig); err != nil {
		return nil, E.WithStr("init ttl probing", err)
	}

	return c, nil
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

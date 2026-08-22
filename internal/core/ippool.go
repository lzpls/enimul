package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lzpls/enimul/internal/dial"
	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/log"
)

const (
	defaultTimeout        = 1 * time.Second
	defaultUpdateInterval = 30 * time.Minute
	defaultMaxConcurrency = 100
	defaultTopIPCount     = 3
	defaultAttempts       = 4
	maxIPPoolSize         = 1000
	weightScaleFactor     = 10000.0
	minWeight             = 1
	maxWeight             = 10000
)

type IPPool struct {
	logger log.Logger
	dialer *dial.Dialer

	waitScanOnStartUp bool
	multi             bool
	ips               []netip.Addr
	fallbackIP        dial.Dst
	port              uint16
	topIPCount        uint8
	attempts          uint8
	timeout           time.Duration
	updateInterval    time.Duration

	mu          sync.RWMutex
	bestIndexes []int
	bestWeights []int
	totalWeight int
	curValidIPs uint32

	scanMu  sync.Mutex
	sem     chan struct{}
	counter atomic.Uint32
}

func (p *IPPool) UnmarshalJSON(b []byte) error {
	var tmp struct {
		WaitScanOnStartUp bool     `json:"wait_scan_on_startup"`
		Multi             bool     `json:"multi"`
		FallbackIP        dial.Dst `json:"fallback_ip"`
		IPs               []string `json:"ips"`
		Port              int      `json:"port"`
		TopIPCount        int      `json:"top_ip_count"`
		MaxConcurrency    int      `json:"max_concurrency"`
		Timeout           string   `json:"timeout"`
		UpdateInterval    string   `json:"update_interval"`
		Attempts          int      `json:"attempts"`
	}
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}

	ips, err := parseIPList(tmp.IPs)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return E.New("no valid IPs after parsing")
	}
	if len(ips) > maxIPPoolSize {
		return fmt.Errorf("IP pool exceeds maximum size (%d): %d", maxIPPoolSize, len(ips))
	}
	if len(ips) < tmp.TopIPCount {
		return fmt.Errorf("IP count (%d) less than top_ip_count (%d)", len(ips), tmp.TopIPCount)
	}

	if tmp.Port <= 0 || tmp.Port > 65535 {
		return fmt.Errorf("invalid port: %d", tmp.Port)
	}

	concurrency := tmp.MaxConcurrency
	if concurrency == 0 {
		concurrency = defaultMaxConcurrency
	} else if concurrency < 1 {
		return fmt.Errorf("invalid max_concurrency: %d", concurrency)
	}

	topCount := tmp.TopIPCount
	if topCount == 0 {
		topCount = defaultTopIPCount
	} else if topCount <= 0 || topCount > 255 || topCount > len(ips) {
		return fmt.Errorf("invalid top_ip_count: %d", topCount)
	}

	attempts := tmp.Attempts
	if attempts == 0 {
		attempts = defaultAttempts
	} else if attempts <= 0 || attempts > 255 {
		return fmt.Errorf("invalid attempts: %d", attempts)
	}

	timeout := defaultTimeout
	if tmp.Timeout != "" {
		timeout, err = time.ParseDuration(tmp.Timeout)
		if err != nil || timeout <= 0 {
			return fmt.Errorf("invalid timeout: %s", tmp.Timeout)
		}
	}

	updateInterval := defaultUpdateInterval
	if tmp.UpdateInterval != "" {
		updateInterval, err = time.ParseDuration(tmp.UpdateInterval)
		if err != nil || updateInterval <= 0 {
			return fmt.Errorf("invalid update_interval: %s", tmp.UpdateInterval)
		}
	}

	if tmp.FallbackIP.IsZero() {
		return E.New("fallback_ip cannot be empty")
	}
	if !tmp.FallbackIP.IsMulti() {
		single := tmp.FallbackIP.Single()
		if single == "" {
			return E.New("fallback_ip cannot be empty")
		}
		switch single[:1] {
		case resolvePrefix, noRedirectPrefix, ipPoolTagPrefix:
		default:
			return fmt.Errorf("invalid fallback_ip: %q", tmp.FallbackIP.Single())
		}
	}
	p.fallbackIP = tmp.FallbackIP

	p.waitScanOnStartUp = tmp.WaitScanOnStartUp
	p.multi = tmp.Multi
	p.ips = ips
	p.port = uint16(tmp.Port)
	p.topIPCount = uint8(topCount)
	p.attempts = uint8(attempts)
	p.timeout = timeout
	p.updateInterval = updateInterval
	p.sem = make(chan struct{}, concurrency)
	p.bestIndexes = make([]int, topCount)
	p.bestWeights = make([]int, topCount)
	return nil
}

func parseIPList(sources []string) ([]netip.Addr, error) {
	ips := make([]netip.Addr, 0)
	for _, pattern := range sources {
		for _, s := range expandPattern(pattern) {
			if len(ips) >= maxIPPoolSize {
				return nil, fmt.Errorf("IP pool exceeds maximum size (%d) during parsing", maxIPPoolSize)
			}
			if addr, err := netip.ParseAddr(s); err == nil && addr.IsValid() {
				ips = append(ips, addr.Unmap())
				continue
			}
			if prefix, err := netip.ParsePrefix(s); err == nil {
				addr := prefix.Addr()
				for prefix.Contains(addr) {
					if len(ips) >= maxIPPoolSize {
						return nil, fmt.Errorf("CIDR %s exceeds max pool size (%d)", s, maxIPPoolSize)
					}
					ips = append(ips, addr.Unmap())
					next := addr.Next()
					if !next.IsValid() || !prefix.Contains(next) {
						break
					}
					addr = next
				}
				continue
			}
			addrs, err := net.LookupIP(s)
			if err != nil {
				return nil, fmt.Errorf("DNS lookup failed for %s: %w", s, err)
			}
			for _, ip := range addrs {
				if addr, ok := netip.AddrFromSlice(ip); ok && addr.IsValid() {
					if len(ips) >= maxIPPoolSize {
						return nil, fmt.Errorf("DNS resolution for %s exceeds max pool size", s)
					}
					ips = append(ips, addr.Unmap())
				}
			}
		}
	}
	return ips, nil
}

func (p *IPPool) Init(logger log.Logger, dialer *dial.Dialer) {
	p.logger = logger
	p.dialer = dialer
	if p.waitScanOnStartUp {
		p.scan()
		go p.monitor()
	} else {
		go func() {
			p.scan()
			p.monitor()
		}()
	}
}

type ipResult struct {
	ipIndex int
	latency time.Duration
	loss    float64
}

func (p *IPPool) scan() {
	p.scanMu.Lock()
	defer p.scanMu.Unlock()

	results := make(chan ipResult, len(p.ips))
	var wg sync.WaitGroup

	p.logger.Info("Testing...")

	for i := range p.ips {
		wg.Go(func() {
			p.sem <- struct{}{}
			defer func() { <-p.sem }()
			latency, loss := p.testIP(i)
			results <- ipResult{i, latency, loss}
		})
	}

	wg.Wait()
	close(results)

	validResults := make([]ipResult, 0, len(p.ips))
	for res := range results {
		if res.loss < 1.0 {
			validResults = append(validResults, res)
		}
	}

	p.updateBest(validResults)
}

func (p *IPPool) testIP(index int) (time.Duration, float64) {
	var (
		successCount int64
		totalLatency time.Duration
	)
	ip := p.ips[index]
	isIPv6 := ip.Is6()
	dialer := net.Dialer{Timeout: p.timeout}
	raddr := netip.AddrPortFrom(ip, p.port)

	for range p.attempts {
		start := time.Now()
		conn, err := dialer.DialTCP(context.Background(), "tcp", p.dialer.GetLocalAddr(isIPv6), raddr)
		if err != nil {
			continue
		}
		totalLatency += time.Since(start)
		conn.Close()
		successCount++
	}

	lossRate := 1.0 - float64(successCount)/float64(p.attempts)
	if successCount == 0 {
		return time.Duration(math.MaxInt64), lossRate
	}
	latency := totalLatency / time.Duration(successCount)
	p.logger.Debug("ip=", p.ips[index], " latency=", latency, " loss=", fmt.Sprintf("%.2f%%", lossRate*100))
	return latency, lossRate
}

func (p *IPPool) updateBest(results []ipResult) {
	if len(results) == 0 {
		return
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].loss != results[j].loss {
			return results[i].loss < results[j].loss
		}
		return results[i].latency < results[j].latency
	})

	p.mu.Lock()
	defer p.mu.Unlock()

	var validCount, totalWeight int
	for i := 0; i < int(p.topIPCount) && i < len(results); i++ {
		res := results[i]
		p.bestIndexes[i] = res.ipIndex

		latencyMs := float64(res.latency) / float64(time.Millisecond)
		weightVal := weightScaleFactor / (latencyMs*(1.0+res.loss) + 1e-5)
		if weightVal < minWeight {
			weightVal = minWeight
		} else if weightVal > maxWeight {
			weightVal = maxWeight
		}
		weight := int(weightVal)
		p.bestWeights[i] = weight
		totalWeight += weight
		validCount++
	}

	for i := validCount; i < int(p.topIPCount); i++ {
		p.bestWeights[i] = 0
	}

	var builder strings.Builder
	builder.Grow(len("Current best IPs: ") + validCount*17)
	builder.WriteString("Current best IPs: ")
	for _, index := range p.bestIndexes[:validCount] {
		builder.WriteString(p.ips[index].String())
		builder.WriteByte(' ')
	}
	p.logger.Info(builder.String())

	p.curValidIPs = uint32(validCount)
	p.totalWeight = totalWeight
}

func (p *IPPool) monitor() {
	for range time.Tick(p.updateInterval) {
		p.scan()
	}
}

func (p *IPPool) Get() *dial.Dst {
	p.mu.RLock()
	validCount := p.curValidIPs
	if validCount == 0 {
		p.mu.RUnlock()
		return &p.fallbackIP
	}
	indexes := append([]int(nil), p.bestIndexes[:validCount]...)
	if p.multi {
		p.mu.RUnlock()
		addrs := make([]netip.Addr, validCount)
		for i := range addrs {
			addrs[i] = p.ips[indexes[i]]
		}
		return dial.NewDstFromAddrs(addrs)
	}
	weights := append([]int(nil), p.bestWeights[:validCount]...)
	total := p.totalWeight
	p.mu.RUnlock()

	current := p.counter.Add(1) - 1
	target := int(current) % total
	acc := 0
	for i := range validCount {
		acc += weights[i]
		if acc > target {
			return dial.NewSingleDst(p.ips[indexes[i]].String())
		}
	}
	return &p.fallbackIP
}

func (c *Core) getIPPool(tag string) (*IPPool, error) {
	if c.ipPools == nil || c.ipPools.Len() == 0 {
		return nil, E.New("no ip pools")
	}
	if ipPool, exists := c.ipPools.Get(tag); exists {
		return ipPool, nil
	}
	return nil, E.New("ip pool " + tag + " does not exist")
}

func (c *Core) getDstFromIPPool(tag string) (cur *dial.Dst, err error) {
	pool, err := c.getIPPool(tag)
	if err != nil {
		return nil, err
	}
	return pool.Get(), nil
}

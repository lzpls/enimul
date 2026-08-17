package dial

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	E "github.com/lzpls/enimul/internal/errors"
)

const defaultDialDelay = 300 * time.Millisecond

type Dst struct {
	single      string
	singleValid bool
	multi       []netip.AddrPort
}

func addrportToString(ap netip.AddrPort) string {
	if ap.Port() == 0 {
		return ap.Addr().String()
	}
	return ap.String()
}

func (d *Dst) String() string {
	if d == nil {
		return ""
	}
	if d.multi == nil {
		return d.single
	}
	if len(d.multi) == 1 {
		return addrportToString(d.multi[0])
	}
	var buf strings.Builder
	buf.WriteByte('[')
	buf.WriteString(addrportToString(d.multi[0]))
	for _, addr := range d.multi[1:] {
		buf.WriteByte(' ')
		buf.WriteString(addrportToString(addr))
	}
	buf.WriteByte(']')
	return buf.String()
}

func NewSingleDst(s string) *Dst { return &Dst{single: s, singleValid: true} }

func NewDstFromAddrs(addrs []netip.Addr) *Dst {
	dst := Dst{multi: make([]netip.AddrPort, len(addrs))}
	for i, addr := range addrs {
		dst.multi[i] = netip.AddrPortFrom(addr, 0)
	}
	return &dst
}

func NewDstFromIPs(ips []net.IP) *Dst {
	dst := Dst{multi: make([]netip.AddrPort, len(ips))}
	for i, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			panic("invalid net.IP")
		}
		dst.multi[i] = netip.AddrPortFrom(addr, 0)
	}
	return &dst
}

func (d *Dst) IsMulti() bool { return d != nil && d.multi != nil }

func (d *Dst) Single() string {
	if d == nil {
		return ""
	}
	if d.singleValid {
		return d.single
	}
	if d.single != "" {
		panic(fmt.Sprintf("invalid state: singleValid is false, but single is %q", d.single))
	}
	return ""
}

func (d *Dst) IsZero() bool {
	return d == nil || (!d.singleValid && d.multi == nil)
}

func (d *Dst) UnmarshalJSON(data []byte) error {
	se := json.Unmarshal(data, &d.single)
	if se == nil {
		d.singleValid = true
		return nil
	}
	var multi []string
	me := json.Unmarshal(data, &multi)
	if me != nil {
		return E.Join(se, me)
	}
	if len(multi) < 2 {
		return E.New("the number of addresses must be greater than 1")
	}
	addrs := make([]netip.AddrPort, len(multi))
	for i, s := range multi {
		if addrport, err := netip.ParseAddrPort(s); err == nil {
			addrs[i] = addrport
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			addrs[i] = netip.AddrPortFrom(addr, 0)
			continue
		}
		return E.New("invalid address: " + s)
	}
	d.multi = addrs
	return nil
}

func DialContextMulti(ctx context.Context, network string, dst *Dst, port string, dialDelay time.Duration) (net.Conn, error) {
	if dst.IsMulti() {
		return dialParallel(ctx, dst.multi, port, dialDelay)
	}
	return NewDialer(dst.single[0] == '[').DialContext(ctx, network, net.JoinHostPort(dst.single, port))
}

func DialTimeoutMulti(ctx context.Context, network string, dst *Dst, port string, timeout time.Duration, dialDelay time.Duration) (net.Conn, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return DialContextMulti(timeoutCtx, network, dst, port, dialDelay)
}

func DialTCPTimeoutMulti(dst *Dst, port string, timeout time.Duration, dialDelay time.Duration) (net.Conn, error) {
	return DialTimeoutMulti(context.Background(), "tcp", dst, port, timeout, dialDelay)
}

func dialParallel(ctx context.Context, addrs []netip.AddrPort, portStr string, dialDelay time.Duration) (net.Conn, error) {
	switch len(addrs) {
	case 0:
		return nil, E.New("no addresses to dial")
	case 1:
		raddr := addrs[0]
		return NewDialer(addrportIs6(raddr)).DialTCP(ctx, "tcp", netip.AddrPort{}, raddr)
	}

	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	port := uint16(p)

	if dialDelay <= 0 {
		dialDelay = defaultDialDelay
	}

	type dialResult struct {
		conn *net.TCPConn
		err  error
	}
	resultCh := make(chan dialResult, len(addrs))

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	wg.Go(func() {
		var prevFailed chan struct{}
		for i, addr := range addrs {
			if i > 0 {
				timer := time.NewTimer(dialDelay)
				select {
				case <-timer.C:
				case <-prevFailed:
					timer.Stop()
				case <-dialCtx.Done():
					timer.Stop()
					return
				}
			}

			select {
			case <-dialCtx.Done():
				return
			default:
			}

			currFailed := make(chan struct{}, 1)
			wg.Go(func() {
				ip := addr.Addr().Unmap()
				if addr.Port() == 0 {
					addr = netip.AddrPortFrom(ip, port)
				}
				dialer := NewDialer(ip.Is6())
				conn, err := dialer.DialTCP(dialCtx, "tcp", netip.AddrPort{}, addr)
				if err != nil {
					select {
					case currFailed <- struct{}{}:
					default:
					}
				}
				resultCh <- dialResult{conn, err}
			})
			prevFailed = currFailed
		}
	})

	go func() {
		wg.Wait()
		close(resultCh)
		for r := range resultCh {
			if r.conn != nil {
				r.conn.Close()
			}
		}
	}()

	var errs []error
	for r := range resultCh {
		if r.err == nil {
			cancel()
			return r.conn, nil
		}
		errs = append(errs, r.err)
	}

	return nil, E.Join(errs...)
}

func addrportIs6(ap netip.AddrPort) bool { return ap.Addr().Unmap().Is6() }

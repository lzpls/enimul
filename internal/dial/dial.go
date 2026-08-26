package dial

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/log"
)

type Dialer struct {
	logger    log.Logger
	localIPv4 atomic.Pointer[net.TCPAddr]
	localIPv6 atomic.Pointer[net.TCPAddr]
	stopCh    chan struct{}
	stopOnce  sync.Once
}

func (d *Dialer) Close() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
	})
}

func (d *Dialer) GetLocalAddr(isIPv6 bool) netip.AddrPort {
	if isIPv6 {
		return d.localIPv6.Load().AddrPort()
	}
	return d.localIPv4.Load().AddrPort()
}

func (d *Dialer) DialContextMulti(ctx context.Context, dst *Dst, port string, dialDelay time.Duration) (*net.TCPConn, error) {
	if dst.IsMulti() {
		return d.dialParallel(ctx, dst.multi, port, dialDelay)
	}
	raddr := net.JoinHostPort(dst.single, port)
	var laddr *net.TCPAddr
	if raddr[0] == '[' {
		laddr = d.localIPv6.Load()
	} else {
		laddr = d.localIPv4.Load()
	}
	var nd net.Dialer
	if laddr != nil {
		nd.LocalAddr = laddr
	}
	conn, err := nd.DialContext(ctx, "tcp", raddr)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

func (d *Dialer) DialTimeoutMulti(ctx context.Context, dst *Dst, port string, timeout time.Duration, dialDelay time.Duration) (*net.TCPConn, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.DialContextMulti(timeoutCtx, dst, port, dialDelay)
}

func (d *Dialer) dialParallel(ctx context.Context, addrs []netip.AddrPort, portStr string, dialDelay time.Duration) (*net.TCPConn, error) {
	if len(addrs) == 0 {
		return nil, E.New("no addresses to dial")
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	port := uint16(p)
	if len(addrs) == 1 {
		ip := addrs[0].Addr().Unmap()
		return new(net.Dialer).DialTCP(ctx, "tcp", d.GetLocalAddr(ip.Is6()), netip.AddrPortFrom(ip, port))
	}

	if dialDelay <= 0 {
		dialDelay = defaultDialDelay
	}

	connCh := make(chan *net.TCPConn, 1)
	errCh := make(chan error, len(addrs))

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	var dialer net.Dialer

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
				conn, err := dialer.DialTCP(dialCtx, "tcp", d.GetLocalAddr(ip.Is6()), addr)

				if err != nil {
					currFailed <- struct{}{}
					errCh <- err
					return
				}

				select {
				case connCh <- conn:
					cancel()
				default:
					conn.Close()
				}
			})
			prevFailed = currFailed
		}
	})

	go func() {
		wg.Wait()
		close(connCh)
		close(errCh)
		for conn := range connCh {
			conn.Close()
		}
	}()

	select {
	case conn, ok := <-connCh:
		if ok {
			return conn, nil
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	return nil, E.Join(errs...)
}

type laddrMonitor = func() (ipv4 net.IP, ipv6 net.IP, zone string, err error)

func (d *Dialer) startMonitor(interval time.Duration, lm laddrMonitor) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			d.logger.Debug("Local address monitor stopped")
			return
		case <-ticker.C:
			ipv4, ipv6, zone, err := lm()
			if err != nil {
				d.logger.Error("Failed to update local address: ", err)
				continue
			}
			msg := []any{"Local address updated:"}
			if ipv4 != nil {
				d.localIPv4.Store(&net.TCPAddr{IP: ipv4})
				msg = append(msg, " ipv4=", ipv4)
			}
			if ipv6 != nil {
				d.localIPv6.Store(&net.TCPAddr{IP: ipv6, Zone: zone})
				msg = append(msg, " ipv6=", ipv6)
			}
			if zone != "" {
				msg = append(msg, " zone=\"", zone, "\"")
			}
			d.logger.Info(msg...)
		}
	}
}

func NewDialer(logger log.Logger, o BindingOption) (*Dialer, error) {
	var (
		ipv4, ipv6   net.IP
		zone         string
		laddrMonitor laddrMonitor
	)
	switch o.Method {
	case MethodOff:
	case MethodSelectInterface:
		interfaces, err := getFilteredInterfaces()
		if err != nil {
			return nil, err
		}
		var selected *networkInterface
		var ok bool
		if o.Zone != "" {
			selected, ok = interfaces.find(o.Zone)
			if !ok {
				return nil, E.New("interface not found: " + o.Zone)
			}
			zone = o.Zone
		} else if o.ManualSelect {
			selected = interfaces.manualSelect()
			zone = selected.name
		} else {
			selected, ok = interfaces.autoSelect(o.PreferredPrefix)
			if !ok {
				fmt.Fprintln(os.Stderr, "No interface with gateway detected")
				selected = interfaces.manualSelect()
				zone = selected.name
			}
		}
		ipv4, ipv6 = selected.ipv4, selected.ipv6
		if o.UpdateInterval > 0 {
			laddrMonitor = func() (net.IP, net.IP, string, error) {
				interfaces, err := getFilteredInterfaces()
				if err != nil {
					return nil, nil, "", err
				}
				var selected *networkInterface
				var ok bool
				if zone == "" {
					selected, ok = interfaces.autoSelect(o.PreferredPrefix)
					if !ok {
						return nil, nil, "", E.New("no suitable interface detected")
					}
				} else {
					selected, ok = interfaces.find(zone)
					if !ok {
						return nil, nil, "", E.New("interface not found: " + zone)
					}
				}
				return selected.ipv4, selected.ipv6, selected.name, nil
			}
		}
	case MethodDialDetect:
		network := "udp"
		if o.DialTCP {
			network = "tcp"
		}
		var err error
		if o.DialIPv4Target != "" {
			ipv4, _, err = detectByDial(network, o.DialIPv4Target, o.DialTimeout)
			if err != nil {
				return nil, err
			}
		}
		if o.DialIPv6Target != "" {
			ipv6, zone, err = detectByDial(network, o.DialIPv6Target, o.DialTimeout)
			if err != nil {
				return nil, err
			}
		}
		if o.UpdateInterval > 0 {
			laddrMonitor = func() (ipv4, ipv6 net.IP, zone string, err error) {
				var err1, err2 error
				if o.DialIPv4Target != "" {
					ipv4, _, err1 = detectByDial(network, o.DialIPv4Target, o.DialTimeout)
				}
				if o.DialIPv6Target != "" {
					ipv6, zone, err2 = detectByDial(network, o.DialIPv6Target, o.DialTimeout)
				}
				err = E.Join(err1, err2)
				return
			}
		}
	case MethodCustom:
		ipv4, ipv6, zone = o.CustomIPv4, o.CustomIPv6, o.CustomZone
	}

	d := Dialer{stopCh: make(chan struct{})}
	if ipv4 != nil {
		d.localIPv4.Store(&net.TCPAddr{IP: ipv4})
	}
	if ipv6 != nil {
		d.localIPv6.Store(&net.TCPAddr{IP: ipv6, Zone: zone})
	}
	if laddrMonitor != nil {
		go d.startMonitor(o.UpdateInterval, laddrMonitor)
	}
	return &d, nil
}

func detectByDial(network, target string, timeout time.Duration) (net.IP, string, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := net.DialTimeout(network, target, timeout)
	if err != nil {
		return nil, "", E.WithStr("dial detect", err)
	}
	defer conn.Close()
	switch laddr := conn.LocalAddr().(type) {
	case *net.TCPAddr:
		return laddr.IP, laddr.Zone, nil
	case *net.UDPAddr:
		return laddr.IP, laddr.Zone, nil
	}
	return nil, "", E.New("unexpected network")
}

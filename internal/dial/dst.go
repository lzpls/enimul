package dial

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
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

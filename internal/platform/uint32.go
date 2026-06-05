//go:build arm || 386 || mips || mipsle || ppc

package platform

func Uint(n int) uint32 {
	return uint32(n)
}

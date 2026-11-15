//go:build !linux

package core

import (
	"io"
	"net"

	"github.com/lzpls/enimul/internal/buffer"
)

func copyDirection(dst, src *net.TCPConn) error {
	buf := buffer.Get(32 << 10)
	defer buffer.Put(buf)
	_, err := io.CopyBuffer(dst, src, buf)
	return err
}

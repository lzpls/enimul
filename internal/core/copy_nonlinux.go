//go:build !linux

package core

import (
	"io"
	"net"
	"sync"
)

const bufferSize = 32 << 10

type buffer = [bufferSize]byte

var bufferPool = sync.Pool{New: func() any { return new(buffer) }}

func copyDirection(dst, src *net.TCPConn) error {
	buf := bufferPool.Get().(*buffer)
	defer bufferPool.Put(buf)
	_, err := io.CopyBuffer(dst, src, buf[:])
	return err
}

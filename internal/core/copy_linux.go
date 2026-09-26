//go:build linux

package core

import (
	"io"
	"net"
)

func copyDirection(dst, src *net.TCPConn) error {
	_, err := io.CopyBuffer(dst, src, nil)
	return err
}

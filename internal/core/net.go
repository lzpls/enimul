package core

import (
	"net"
	"syscall"

	E "github.com/lzpls/enimul/internal/errors"
)

func getRawConn[T syscall.Conn](conn T) (syscall.RawConn, error) {
	rawConn, err := conn.SyscallConn()
	return rawConn, E.WithStr("get raw conn", err)
}

func listenTCP(addrStr string) (*net.TCPListener, error) {
	addr, err := net.ResolveTCPAddr("tcp", addrStr)
	if err != nil {
		return nil, err
	}
	return net.ListenTCP("tcp", addr)
}

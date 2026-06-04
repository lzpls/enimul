//go:build windows

package core

import (
	"net"
	"syscall"
	"unsafe"

	E "github.com/lzpls/enimul/internal/errors"

	"golang.org/x/sys/windows"
)

func sendWithOOB(conn net.Conn, data []byte, oob byte) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return err
	}

	var toSend []byte
	if data == nil {
		toSend = []byte{oob}
	} else {
		toSend = make([]byte, len(data)+1)
		copy(toSend, data)
		toSend[len(data)] = oob
	}
	wsabuf := syscall.WSABuf{
		Len: uint32(len(toSend)),
		Buf: unsafe.SliceData(toSend),
	}
	var n uint32
	var innerErr error
	if err = rawConn.Write(func(fd uintptr) (done bool) {
		innerErr = syscall.WSASend(
			syscall.Handle(fd),
			&wsabuf,
			1,
			&n,
			windows.MSG_OOB,
			nil,
			nil,
		)
		return true
	}); err != nil {
		return E.WithStr("raw write (wsasend)", err)
	}
	return E.WithStr("wsasend (MSG_OOB)", innerErr)
}

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

	var buf []byte
	if data == nil {
		buf = []byte{oob}
	} else {
		buf = make([]byte, len(data)+1)
		copy(buf, data)
		buf[len(data)] = oob
	}
	wsabuf := syscall.WSABuf{
		Buf: unsafe.SliceData(buf),
		Len: uint32(len(buf)),
	}
	var n uint32
	var sendErr error
	if err = rawConn.Write(func(fd uintptr) (done bool) {
		sendErr = syscall.WSASend(
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
		return E.WithStr("raw write", err)
	}
	return E.WithStr("wsasend (MSG_OOB)", sendErr)
}

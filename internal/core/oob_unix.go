//go:build unix

package core

import (
	"net"
	"syscall"

	E "github.com/lzpls/enimul/internal/errors"
)

func sendWithOOB(conn net.Conn, data []byte, oob byte) error {
	// Tested on Android; did not work as expected.
	rawConn, err := getRawConn(conn)
	if err != nil {
		return err
	}

	toSend := make([]byte, len(data)+1)
	copy(toSend, data)
	toSend[len(data)] = oob

	var innerErr error
	if err = rawConn.Write(func(fd uintptr) (done bool) {
		for {
			innerErr = syscall.Sendto(int(fd), toSend, syscall.MSG_OOB, nil)
			if innerErr == syscall.EINTR {
				continue
			}
			return true
		}
	}); err != nil {
		return E.WithStr("raw write (send)", err)
	}
	return E.WithStr("send (MSG_OOB)", innerErr)
}

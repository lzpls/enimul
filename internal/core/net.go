package core

import (
	"bufio"
	"errors"
	"net"
	"sync/atomic"
	"syscall"

	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/log"
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

func drainBuffered(logger log.Logger, br *bufio.Reader, dst *net.TCPConn) bool {
	if n := br.Buffered(); n > 0 {
		buf, err := br.Peek(n)
		if err != nil {
			logger.Error("Read buffered data: ", err)
			return false
		}
		if _, err := dst.Write(buf); err != nil {
			logger.Error("Send drained buffered data: ", err)
			return false
		}
	}
	return true
}

func forwardTCP(logger log.Logger, srcConn, dstConn *net.TCPConn, dstAddr string) {
	logger.Info("Start forwarding")
	closeBoth := func() {
		dstConn.Close()
		srcConn.Close()
	}
	var done atomic.Bool
	go func() {
		if err := copyDirection(dstConn, srcConn); err != nil {
			closeBoth()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Error("Forward ", srcConn.RemoteAddr(), "->", dstAddr, ": ", err)
			return
		}
		logger.Debug("Forward ", srcConn.RemoteAddr(), "->", dstAddr, " finished")
		if err := dstConn.CloseWrite(); err != nil || done.Swap(true) {
			closeBoth()
		}
	}()
	go func() {
		if err := copyDirection(srcConn, dstConn); err != nil {
			closeBoth()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Error("Forward ", dstAddr, "->", srcConn.RemoteAddr(), ": ", err)
			return
		}
		logger.Debug("Forward ", dstAddr, "->", srcConn.RemoteAddr(), " finished")
		if err := srcConn.CloseWrite(); err != nil || done.Swap(true) {
			closeBoth()
		}
	}()
}

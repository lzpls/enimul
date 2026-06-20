//go:build linux

package core

import (
	"syscall"
	"time"
	"unsafe"

	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/platform"

	"golang.org/x/sys/unix"
)

func sendWithNoise(
	rawConn syscall.RawConn,
	fakeData, realData []byte,
	fakeTTL, defaultTTL, level, opt int,
	fakeSleep time.Duration,
) error {
	var sockFD int
	if err := rawConn.Control(func(raw uintptr) {
		sockFD = int(raw)
	}); err != nil {
		return E.WithStr("raw control", err)
	}

	pipe, err := getPipe()
	if err != nil {
		return err
	}
	defer putPipe(pipe)

	pageSize := syscall.Getpagesize()
	nPages := (len(fakeData) + pageSize - 1) / pageSize
	mmapLen := nPages * pageSize
	data, err := syscall.Mmap(-1, 0, mmapLen,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return E.WithStr("mmap", err)
	}
	defer syscall.Munmap(data)
	copy(data, fakeData)

	if err := syscall.SetsockoptInt(sockFD, level, opt, fakeTTL); err != nil {
		return E.WithStr("set fake ttl", err)
	}
	if _, err := unix.Vmsplice(pipe.wfd, []unix.Iovec{{
		Base: unsafe.SliceData(data),
		Len:  platform.Uint(len(fakeData)),
	}}, unix.SPLICE_F_GIFT); err != nil {
		return E.WithStr("vmsplice", err)
	}
	pipe.hasData = true

	var rawWriteErr, spliceErr error
	done := make(chan struct{})
	go func() {
		remaining := len(fakeData)
		rawWriteErr = rawConn.Write(func(fd uintptr) (done bool) {
			for remaining > 0 {
				n, err := syscall.Splice(
					pipe.rfd, nil,
					int(fd), nil,
					remaining,
					unix.SPLICE_F_NONBLOCK,
				)
				if spliceErr = err; spliceErr == syscall.EINTR {
					continue
				}
				remaining -= int(n)
				if spliceErr != nil {
					return spliceErr != syscall.EAGAIN
				}
			}
			pipe.hasData = false
			return true
		})
		close(done)
	}()

	time.Sleep(fakeSleep)

	copy(data, realData) // will be sent automatically by the system.

	if err := syscall.SetsockoptInt(sockFD, level, opt, defaultTTL); err != nil {
		return E.WithStr("set default ttl", err)
	}

	<-done
	if rawWriteErr != nil {
		return E.WithStr("raw write", rawWriteErr)
	}
	return E.WithStr("splice", spliceErr)
}

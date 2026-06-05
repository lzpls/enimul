//go:build linux

package core

import (
	"net"
	"syscall"
	"time"
	"unsafe"

	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/platform"

	"golang.org/x/sys/unix"
)

func setsockoptInt(fd uintptr, level, opt, value int) error {
	return E.WithStr("setsockopt", syscall.SetsockoptInt(int(fd), level, opt, value))
}

func sendWithNoise(
	socketFD int, rawConn syscall.RawConn,
	fakeData, realData []byte,
	fakeTTL, defaultTTL, level, opt int,
	fakeSleep time.Duration,
) error {
	// TODO: cache pipes with a sync.Pool
	var pipeFDs [2]int
	if err := syscall.Pipe2(pipeFDs[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		return E.WithStr("create pipe", err)
	}
	pipeR, pipeW := pipeFDs[0], pipeFDs[1]
	defer syscall.Close(pipeR)
	defer syscall.Close(pipeW)

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

	if err := syscall.SetsockoptInt(socketFD, level, opt, fakeTTL); err != nil {
		return E.WithStr("set fake TTL", err)
	}
	if _, err := unix.Vmsplice(pipeW, []unix.Iovec{{
		Base: unsafe.SliceData(data),
		Len:  platform.Uint(len(fakeData)),
	}}, unix.SPLICE_F_GIFT); err != nil {
		return E.WithStr("vmsplice", err)
	}

	var rawWriteErr, innerErr error
	done := make(chan struct{})
	go func() {
		remaining := len(fakeData)
		rawWriteErr = rawConn.Write(func(fd uintptr) (done bool) {
			for remaining > 0 {
				n, err := syscall.Splice(
					pipeR, nil,
					int(fd), nil,
					remaining,
					unix.SPLICE_F_NONBLOCK,
				)
				if err == syscall.EINTR {
					continue
				}
				remaining -= int(n)
				innerErr = err
				if innerErr != nil {
					return innerErr != syscall.EAGAIN
				}
			}
			return true
		})
		close(done)
	}()

	time.Sleep(fakeSleep)

	copy(data, realData) // will be sent automatically by the system.

	if err := syscall.SetsockoptInt(socketFD, level, opt, defaultTTL); err != nil {
		return E.WithStr("set default TTL", err)
	}

	<-done
	if rawWriteErr != nil {
		return E.WithStr("raw write (splice)", rawWriteErr)
	}
	return E.WithStr("splice", innerErr)
}

func desyncSend(
	conn net.Conn, isIPv6 bool,
	record []byte, sniStart, sniLen int,
	fakeTTL int, fakeSleep time.Duration,
) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return err
	}

	var fd int
	if err = rawConn.Control(func(fileDesc uintptr) {
		fd = int(fileDesc)
	}); err != nil {
		return E.WithStr("raw control", err)
	}

	level, opt := ttlLevelOption(isIPv6)
	defaultTTL, err := unix.GetsockoptInt(fd, level, opt)
	if err != nil {
		return E.WithStr("get default TTL", err)
	}

	cut := findLastDotOrMidPos(record, sniStart, sniLen)
	fakeData := make([]byte, cut)
	copy(fakeData, record[:sniStart])
	fakeSleep = max(minInterval, fakeSleep)

	if err = sendWithNoise(
		fd, rawConn,
		fakeData,
		record[:cut],
		fakeTTL,
		defaultTTL,
		level, opt,
		fakeSleep,
	); err != nil {
		return E.WithStr("send data with noise", err)
	}
	if _, err = conn.Write(record[cut:]); err != nil {
		return E.WithStr("send remaining data", err)
	}
	return nil
}

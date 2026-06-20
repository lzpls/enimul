// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package core

import (
	"runtime"
	"sync"
	"syscall"
)

// Modified from Go 1.26.0 internal/pool/splice_linux.go

type splicePipeFields struct {
	rfd  int
	wfd  int
	hasData bool
}

type splicePipe struct {
	splicePipeFields
	cleanup runtime.Cleanup
}

// pipePool caches pipes to avoid high-frequency construction and destruction of pipe buffers.
// The garbage collector will free all pipes in the sync.Pool periodically, thus we need to set up
// a finalizer for each pipe to close its file descriptors before the actual GC.
var pipePool = sync.Pool{New: newPoolPipe}

func newPoolPipe() any {
	// Discard the error which occurred during the creation of pipe buffer,
	// redirecting the data transmission to the conventional way utilizing read() + write() as a fallback.
	p := newPipe()
	if p == nil {
		return nil
	}

	p.cleanup = runtime.AddCleanup(p, func(spf splicePipeFields) {
		destroyPipe(&splicePipe{splicePipeFields: spf})
	}, p.splicePipeFields)
	return p
}

// getPipe tries to acquire a pipe buffer from the pool or create a new one with newPipe() if it gets nil from the cache.
func getPipe() (*splicePipe, error) {
	v := pipePool.Get()
	if v == nil {
		return nil, syscall.EINVAL
	}
	return v.(*splicePipe), nil
}

func putPipe(p *splicePipe) {
	// If there is still data left in the pipe,
	// then close and discard it instead of putting it back into the pool.
	if p.hasData {
		p.cleanup.Stop()
		destroyPipe(p)
		return
	}
	pipePool.Put(p)
}

// newPipe sets up a pipe for a splice operation.
func newPipe() *splicePipe {
	var fds [2]int
	if err := syscall.Pipe2(fds[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		return nil
	}

	return &splicePipe{splicePipeFields: splicePipeFields{rfd: fds[0], wfd: fds[1]}}
}

// destroyPipe destroys a pipe.
func destroyPipe(p *splicePipe) {
	syscall.Close(p.rfd)
	syscall.Close(p.wfd)
}

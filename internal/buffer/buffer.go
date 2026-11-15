package buffer

import (
	"math/bits"
	"sync"

	F "github.com/lzpls/enimul/internal/fmt"
)

// Modified from https://github.com/SagerNet/sing/blob/27b73774b240c645099704ba533d2615727c3410/common/buf/alloc.go

var pools = [...]sync.Pool{
	{New: func() any { return new([1 << 6]byte) }},
	{New: func() any { return new([1 << 7]byte) }},
	{New: func() any { return new([1 << 8]byte) }},
	{New: func() any { return new([1 << 9]byte) }},
	{New: func() any { return new([1 << 10]byte) }},
	{New: func() any { return new([1 << 11]byte) }},
	{New: func() any { return new([1 << 12]byte) }},
	{New: func() any { return new([1 << 13]byte) }},
	{New: func() any { return new([1 << 14]byte) }},
	{New: func() any { return new([1 << 15]byte) }},
	{New: func() any { return new([1 << 16]byte) }},
}

func Get(size int) []byte {
	if size <= 0 || size > 1<<16 {
		panic("buffer: invalid buffer size " + F.Int(size))
	}

	index := max(uint16(bits.Len32(uint32(size-1))), 6) - 6
	buf := pools[index].Get()
	switch index {
	case 0:
		return buf.(*[1 << 6]byte)[:size]
	case 1:
		return buf.(*[1 << 7]byte)[:size]
	case 2:
		return buf.(*[1 << 8]byte)[:size]
	case 3:
		return buf.(*[1 << 9]byte)[:size]
	case 4:
		return buf.(*[1 << 10]byte)[:size]
	case 5:
		return buf.(*[1 << 11]byte)[:size]
	case 6:
		return buf.(*[1 << 12]byte)[:size]
	case 7:
		return buf.(*[1 << 13]byte)[:size]
	case 8:
		return buf.(*[1 << 14]byte)[:size]
	case 9:
		return buf.(*[1 << 15]byte)[:size]
	case 10:
		return buf.(*[1 << 16]byte)[:size]
	}
	panic("buffer: invalid pool index" + F.Uint(index))
}

func Put(buf []byte) {
	c := cap(buf)
	if c < 1<<6 || c > 1<<16 || c&(c-1) != 0 {
		panic("buffer: invalid buffer capacity " + F.Int(c))
	}

	index := uint16(bits.Len32(uint32(c)) - 1 - 6)
	buf = buf[:c]

	switch index {
	case 0:
		pools[index].Put((*[1 << 6]byte)(buf))
	case 1:
		pools[index].Put((*[1 << 7]byte)(buf))
	case 2:
		pools[index].Put((*[1 << 8]byte)(buf))
	case 3:
		pools[index].Put((*[1 << 9]byte)(buf))
	case 4:
		pools[index].Put((*[1 << 10]byte)(buf))
	case 5:
		pools[index].Put((*[1 << 11]byte)(buf))
	case 6:
		pools[index].Put((*[1 << 12]byte)(buf))
	case 7:
		pools[index].Put((*[1 << 13]byte)(buf))
	case 8:
		pools[index].Put((*[1 << 14]byte)(buf))
	case 9:
		pools[index].Put((*[1 << 15]byte)(buf))
	case 10:
		pools[index].Put((*[1 << 16]byte)(buf))
	default:
		panic("buffer: invalid pool index " + F.Uint(index))
	}
}

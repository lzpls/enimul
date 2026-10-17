//go:build !goexperiment.jsonv2

package jsonx

func initOptions() {}

func Unmarshal(in []byte, out any) error { return newDecoderFromBytes(in).Decode(out) }

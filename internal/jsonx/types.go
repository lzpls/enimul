package jsonx

import (
	"encoding/json"
	"errors"
	"time"

	F "github.com/lzpls/enimul/internal/fmt"
)

type Bool uint8

const (
	BoolUnset Bool = iota
	BoolFalse
	BoolTrue
)

func (b Bool) IsTrue() bool { return b == BoolTrue }

func (b Bool) IsUnset() bool { return b == BoolUnset }

func (b *Bool) UnmarshalJSON(data []byte) error {
	s := string(data)
	switch s {
	case "false":
		*b = BoolFalse
	case "true":
		*b = BoolTrue
	default:
		return errors.New("invalid bool: " + s)
	}
	return nil
}

type Byte struct {
	b           byte
	valid, zero bool
}

func (b Byte) Append(buf []byte) []byte { return append(buf, F.Byte(b.b)...) }

func (b Byte) IsUnset() bool { return !b.valid }

func (b Byte) IsZero() bool { return b.IsUnset() || b.zero }

func (b Byte) Byte() byte { return b.b }

func (b *Byte) UnmarshalJSON(data []byte) error {
	b.valid = true
	if string(data) == "false" {
		b.zero = true
		return nil
	}
	if err := json.Unmarshal(data, &b.b); err != nil {
		return err
	}
	return nil
}

type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	duration, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(duration)
	return nil
}

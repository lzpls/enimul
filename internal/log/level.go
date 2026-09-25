package log

import (
	"encoding/json"
	"flag"
	"fmt"

	E "github.com/lzpls/enimul/internal/errors"
)

var _ flag.Value = (*Level)(nil)

type Level int8

const (
	LevelUnset Level = iota
	LevelTrace
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
	Disabled // disables the logger
)

func (l *Level) String() string {
	if l == nil {
		return "<nil>"
	}
	switch *l {
	case LevelUnset:
		return "unknown"
	case LevelTrace:
		return "trace"
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	case Disabled:
		return "disabled"
	}
	panic(fmt.Sprintf("unknown log level %d", *l))
}

func (l *Level) Set(value string) error {
	lvl, err := ParseLevel(value)
	if err != nil {
		return err
	}
	*l = lvl
	return nil
}

func ParseLevel(s string) (Level, error) {
	switch s {
	case "TRACE", "trace":
		return LevelTrace, nil
	case "DEBUG", "debug":
		return LevelDebug, nil
	case "INFO", "info":
		return LevelInfo, nil
	case "WARN", "warn", "WARNING", "warning":
		return LevelWarn, nil
	case "ERROR", "error":
		return LevelError, nil
	case "NONE", "none":
		return Disabled, nil
	}
	return 0, E.New("unknown log level: " + s)
}

func (lvl *Level) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	l, err := ParseLevel(s)
	if err != nil {
		return err
	}
	*lvl = l
	return nil
}

func appendLevel(b []byte, lvl Level) []byte {
	switch lvl {
	case LevelTrace:
		return append(b, "TRACE"...)
	case LevelDebug:
		return append(b, "DEBUG"...)
	case LevelInfo:
		return append(b, "INFO"...)
	case LevelWarn:
		return append(b, "WARN"...)
	case LevelError:
		return append(b, "ERROR"...)
	case LevelUnset:
		panic("appendLevel: unexpected log level LevelUnset")
	case Disabled:
		panic("appendLevel: unexpected log level Disabled")
	}
	panic(fmt.Sprintf("appendLevel: unknown log level %d", lvl))
}

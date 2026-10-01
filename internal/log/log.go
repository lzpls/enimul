package log

import (
	"io"
	"os"
	"path/filepath"
	"time"

	E "github.com/lzpls/enimul/internal/errors"
	F "github.com/lzpls/enimul/internal/fmt"
)

type Logger interface {
	Trace(args ...any)
	Debug(args ...any)
	Info(args ...any)
	Warn(args ...any)
	Error(args ...any)
}

func NewFactory(out io.Writer, lvl Level) *Factory {
	if lvl == Disabled {
		out = io.Discard
	}
	return &Factory{out: out, lvl: lvl}
}

type Factory struct {
	out io.Writer
	lvl Level
}

func (f *Factory) NewLogger(prefix string) Logger {
	return &consoleLogger{out: f.out, lvl: f.lvl, prefix: prefix}
}

func NewOutput(out string) (io.Writer, error) {
	switch out {
	case "", "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	default:
		out = os.ExpandEnv(out)
		if dir := filepath.Dir(out); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, E.WithStr("create log directory", err)
			}
		}
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return nil, E.WithStr("open log file", err)
		}
		return f, nil
	}
}

func Err(args ...any) {
	bufp := getBuffer()
	defer putBuffer(bufp)
	*bufp = time.Now().AppendFormat(*bufp, defaultTimeFormat)
	*bufp = append(*bufp, ' ')
	*bufp = F.Append(*bufp, args...)
	*bufp = append(*bufp, '\n')
	os.Stderr.Write(*bufp)
}

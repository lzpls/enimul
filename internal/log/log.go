// Package log provides a lightweight, fast logging library.
package log

import "io"

type Logger interface {
	Trace(args ...any)
	Debug(args ...any)
	Info(args ...any)
	Warn(args ...any)
	Error(args ...any)
	//io.Closer
}

func New(out io.Writer, prefix string, lvl Level) Logger {
	if lvl == Disabled {
		out = io.Discard
	}
	return &consoleLogger{out: out, prefix: prefix, lvl: lvl}
}

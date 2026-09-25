package log

import (
	"io"
	"sync"
	"time"

	F "github.com/lzpls/enimul/internal/fmt"
)

const (
	initialBufferSize = 300
	defaultTimeFormat = "2006-01-02 15:04:05.000"
)

var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, initialBufferSize)
		return &buf
	},
}

func getBuffer() *[]byte { return bufferPool.Get().(*[]byte) }

func putBuffer(bufp *[]byte) {
	if cap(*bufp) > 64<<10 {
		*bufp = nil
		return
	}
	*bufp = (*bufp)[:0]
	bufferPool.Put(bufp)
}

type consoleLogger struct {
	out    io.Writer
	lvl    Level
	prefix string
}

func (l *consoleLogger) output(lvl Level, args []any) {
	if lvl < l.lvl {
		return
	}

	bufp := getBuffer()
	defer putBuffer(bufp)

	if l.prefix != "" {
		*bufp = append(*bufp, l.prefix...)
		*bufp = append(*bufp, ' ')
	}

	*bufp = time.Now().AppendFormat(*bufp, defaultTimeFormat)
	*bufp = append(*bufp, ' ')

	*bufp = appendLevel(*bufp, lvl)
	*bufp = append(*bufp, ' ')

	*bufp = F.Append(*bufp, args...)
	*bufp = append(*bufp, '\n')

	if _, err := l.out.Write(*bufp); err != nil {
		F.Errln("log: write failed:", err)
	}
}

func (l *consoleLogger) Trace(args ...any) { l.output(LevelTrace, args) }
func (l *consoleLogger) Debug(args ...any) { l.output(LevelDebug, args) }
func (l *consoleLogger) Info(args ...any)  { l.output(LevelInfo, args) }
func (l *consoleLogger) Warn(args ...any)  { l.output(LevelWarn, args) }
func (l *consoleLogger) Error(args ...any) { l.output(LevelError, args) }

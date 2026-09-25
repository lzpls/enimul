package core

import (
	"os"
	"path/filepath"

	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/log"
)

func (c *Core) setLogOutput(out string) error {
	switch out {
	case "", "stdout":
		c.logOutput = os.Stdout
	case "stderr":
		c.logOutput = os.Stderr
	default:
		out = os.ExpandEnv(out)
		if dir := filepath.Dir(out); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return E.WithStr("create log directory", err)
			}
		}
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return E.WithStr("open log file", err)
		}
		c.logOutput = f
	}
	return nil
}

func (c *Core) newLogger(prefix string) log.Logger {
	return log.New(c.logOutput, prefix, c.logLevel)
}

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/lzpls/enimul/internal/core"
	E "github.com/lzpls/enimul/internal/errors"
	F "github.com/lzpls/enimul/internal/fmt"
	"github.com/lzpls/enimul/internal/jsonx"
	"github.com/lzpls/enimul/internal/log"
	_ "github.com/lzpls/enimul/internal/platform"
)

func main() {
	var (
		logLevel             log.Level
		configPaths          stringArray
		rejectUnknownMembers bool
		maxProcs             int
		runGC                bool
		printLicense         bool
		printVersion         bool
	)
	flag.Var(&logLevel, "ll", "Log level (override config)")
	logOutput := flag.String("lo", "", "Log output (override config)")
	flag.Var(&configPaths, "c", "Config file path or stdin (override environment variable ENIMUL_CONFIG_FILE)")
	socks5Addr := flag.String("b", "", "SOCKS5 listen address (override config)")
	httpAddr := flag.String("hb", "", "HTTP proxy listen address (override config)")
	sniAddr := flag.String("spb", "", "SNI proxy listen address (override config)")
	flag.BoolVar(&rejectUnknownMembers, "duf", false, "Reject configs containing unknown fields")
	flag.IntVar(&maxProcs, "mp", 0, "GOMAXPROCS")
	flag.BoolVar(&runGC, "rungc", false, "Run runtime.GC and debug.FreeOSMemory after initiation")
	flag.BoolVar(&printLicense, "license", false, "Show license and exit")
	flag.BoolVar(&printVersion, "v", false, "Show current version and exit")

	flag.Usage = func() {
		flag.PrintDefaults()
		F.Errln()
		showLicense()
	}
	flag.Parse()

	if printVersion {
		showVersion()
		return
	}

	if printLicense {
		showLicense()
		return
	}

	if len(configPaths) == 0 {
		if env := os.Getenv("ENIMUL_CONFIG_FILE"); env == "" {
			configPaths = stringArray{"config.json"}
		} else {
			configPaths = stringArray{env}
		}
	}

	builder := core.NewBuilder()
	for _, path := range configPaths {
		cfg, err := configFromFile(path, rejectUnknownMembers)
		if err != nil {
			F.Errf("Failed to load config %q: %v", path, err)
			os.Exit(1)
		}
		if err = builder.Merge(cfg); err != nil {
			F.Errf("Failed to merge config %q: %v", path, err)
			os.Exit(1)
		}
	}

	builder.Merge(&core.Config{
		LogLevel:     logLevel,
		LogOutput:    ptrOrNil(logOutput),
		Socks5Addr:   ptrOrNil(socks5Addr),
		HttpAddr:     ptrOrNil(httpAddr),
		SNIProxyAddr: ptrOrNil(sniAddr),
	})

	instance, err := builder.Build()
	if err != nil {
		F.Errln("Failed to build instance:", err)
		os.Exit(1)
	}

	if maxProcs > 0 {
		runtime.GOMAXPROCS(maxProcs)
	}

	startPprofServer()

	done, ok := instance.Serve()
	if !ok {
		F.Errln("No inbound specified")
		os.Exit(1)
	}

	if runGC {
		runtime.GC()
		debug.FreeOSMemory()
	}
	<-done
}

func showVersion() {
	F.Err("lzpls/enimul " + core.Version + " built with " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + "\n")
}

func showLicense() {
	F.Err(`This project is licensed under the GNU Affero General Public License v3.0.
Source code: https://github.com/lzpls/enimul
`)
}

func configFromFile(path string, rejectUnknownMembers bool) (*core.Config, error) {
	var data []byte
	var err error
	if path == "stdin" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, E.WithStr("read config", err)
	}
	cfg, err := decodeConfig(jsonx.ToJSONInPlace(data), rejectUnknownMembers)
	if err != nil {
		return nil, E.WithStr("decode config", err)
	}
	return cfg, nil
}

type stringArray []string

func (s *stringArray) String() string { return fmt.Sprint(*s) }

func (s *stringArray) Set(value string) error {
	if value == "" {
		return E.New("empty string")
	}
	*s = append(*s, value)
	return nil
}

func ptrOrNil(s *string) *string {
	if *s == "" {
		return nil
	}
	return s
}

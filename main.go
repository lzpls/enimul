package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/lzpls/enimul/internal/core"
	F "github.com/lzpls/enimul/internal/fmt"
)

func main() {
	F.Println("lzpls/enimul", core.Version)
	F.Println()
	flag.Usage = func() {
		flag.PrintDefaults()
		F.Println()
		showLicense()
	}
	confPath := flag.String("c", "", "Config file path (override environment variable ENIMUL_CONFIG_FILE)")
	socks5Addr := flag.String("b", "", "SOCKS5 bind address (override config)")
	httpAddr := flag.String("hb", "", "HTTP bind address (override config)")
	sniAddr := flag.String("spb", "", "SNI proxy bind address (override config)")
	maxprocs := flag.Int("mp", 0, "GOMAXPROCS")
	printLicense := flag.Bool("license", false, "Show license and source code information and exit")
	disallowUnknownFields := flag.Bool("duf", false, "Reject config containing unknown fields")
	foregroundReload := flag.Bool("fr", false, "Reload after receiving Ctrl+C")

	flag.Parse()

	if *printLicense {
		showLicense()
		return
	}

	configPath := *confPath
	if configPath == "" {
		configPath = os.Getenv("ENIMUL_CONFIG_FILE")
		if configPath == "" {
			configPath = "config.json"
		}
	}

	if *maxprocs > 0 {
		runtime.GOMAXPROCS(*maxprocs)
	}
	startPprofServer()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer signal.Stop(osSignals)
	for {
		instance := core.Core{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		configSocks5Addr, configHTTPAddr, configSNIAddr, err := instance.Init(ctx, cancel, configPath, *disallowUnknownFields)
		if err != nil {
			F.Println("Failed to load config:", err)
			return
		}
		var wg sync.WaitGroup
		wg.Go(func() { instance.SOCKS5Serve(ctx, *socks5Addr, configSocks5Addr) })
		wg.Go(func() { instance.HTTPServe(ctx, *httpAddr, configHTTPAddr) })
		wg.Go(func() { instance.SNIServe(ctx, *sniAddr, configSNIAddr) })
		go func() {
			wg.Wait()
			instance.Cleanup()
		}()
		sig := <-osSignals
		switch sig {
		case syscall.SIGHUP:
			instance.StopListening()
			go instance.WaitAndCleanup(ctx)
			F.Println("Reloading...")
			continue
		case os.Interrupt:
			if *foregroundReload {
				instance.StopListening()
				go instance.WaitAndCleanup(ctx)
				F.Println("Reloading...")
				continue
			}
			F.Println("Waiting for active connections... Press Ctrl+C again to exit")
		case syscall.SIGTERM:
		}
		done := make(chan struct{}, 1)
		go func() {
			instance.StopListening()
			instance.Wait(ctx)
			done <- struct{}{}
		}()
		for {
			select {
			case sig := <-osSignals:
				if sig == os.Interrupt || sig == syscall.SIGTERM {
					return
				}
			case <-done:
				return
			}
		}
	}
}

func showLicense() {
	F.Println("This project is licensed under the GNU Affero General Public License v3.0.")
	F.Println("Source code: https://github.com/lzpls/enimul")
	F.Println("More: https://www.gnu.org/licenses/agpl-3.0.html")
}

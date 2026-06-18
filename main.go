package main

import (
	"flag"
	"runtime"

	"github.com/lzpls/enimul/internal/core"
	F "github.com/lzpls/enimul/internal/fmt"
)

func main() {
	F.Println("lzpls/enimul", core.Version)
	F.Println()
	flag.Usage = func() { flag.PrintDefaults() }
	configPath := flag.String("c", "config.json", "Config file path")
	addr := flag.String("b", "", "SOCKS5 bind address (default: address from config file)")
	hAddr := flag.String("hb", "", "HTTP bind address (default: address from config file)")
	maxprocs := flag.Int("mp", 0, "GOMAXPROCS")
	flag.Parse()

	socks5Addr, httpAddr, err := core.LoadConfig(*configPath)
	if err != nil {
		F.Println("Failed to load config:", err)
		return
	}

	if *maxprocs > 0 {
		runtime.GOMAXPROCS(*maxprocs)
	}

	startPprofServer()

	runtime.GC()

	done := make(chan struct{})
	go core.SOCKS5Accept(addr, socks5Addr, done)
	core.HTTPAccept(hAddr, httpAddr)
	<-done
}

//go:build !nodebug

package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
)

var pprofServerAddr = flag.String("dp", "", "Debug pprof server bind address")

func startPprofServer() {
	if *pprofServerAddr == "" {
		return
	}
	go func() {
		if err := http.ListenAndServe(*pprofServerAddr, nil); err != nil {
			fmt.Fprintln(os.Stderr, "Debug pprof server listen and serve:", err)
		}
	}()
}

//go:build windows && cli

package main

// Console build (go build -tags cli): same engine, logs to the terminal.

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var cfg config
	registerFlags(&cfg)
	verbose := flag.Bool("v", false, "log every split packet")
	quiet := flag.Bool("q", false, "don't log hostnames")
	noElevate := flag.Bool("no-elevate", false, "don't try to relaunch as administrator")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "dpisplit-cli %s\n\nUsage: dpisplit-cli.exe [options]\n\n", version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if !isElevated() {
		if *noElevate {
			fatal("administrator rights are required")
		}
		if err := relaunchElevated(); err != nil {
			fatal("could not relaunch as administrator: %v", err)
		}
		return
	}
	if !acquireSingleInstance() {
		fatal("dpisplit is already running (the app, another console, or a scheduled task). Stop it first.")
	}

	eng := &engine{
		onFail: func(err error) { fatal("%v", err) },
	}
	switch {
	case *verbose:
		eng.verbose = func(host, detail string) { fmt.Printf("split  %-40s %s\n", host, detail) }
	case !*quiet:
		eng.onHost = func(host string) { fmt.Printf("split  %s\n", host) }
	}

	fmt.Printf("dpisplit-cli %s\n  %s\n", version, cfg.describe())
	if err := eng.Start(cfg); err != nil {
		fatal("%v", err)
	}
	fmt.Println("Running. Press Ctrl+C or close this window to stop.")
	fmt.Println()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	fmt.Println("\nStopping...")
	eng.Stop()
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "\nERROR: "+format+"\n", a...)
	fmt.Fprint(os.Stderr, "Press Enter to exit...")
	bufio.NewReader(os.Stdin).ReadString('\n')
	os.Exit(1)
}

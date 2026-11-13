package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/daemon"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"

func main() {
	path := flag.String("config", "/etc/minging-agent/agent.json", "private configuration file")
	show := flag.Bool("version", false, "print version")
	flag.Parse()
	if *show {
		fmt.Println("Minging_Net_v2_agent " + version)
		return
	}
	c, e := daemon.Load(*path)
	if e != nil {
		slog.Error("configuration rejected", "error", e)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e = daemon.Run(ctx, c, version); e != nil {
		slog.Error("agent stopped", "error", e)
		os.Exit(1)
	}
}

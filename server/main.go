package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vulns-news/src/scanjob"
)

func main() {
	binary := flag.String("scanner", "", "required path to trusted prebuilt repo-scan executable")
	addr := flag.String("addr", "127.0.0.1:8080", "listen address (non-loopback exposes an unauthenticated API)")
	workers := flag.Int("workers", 2, "maximum concurrent scans")
	capacity := flag.Int("capacity", 100, "maximum retained jobs, including queued/running jobs")
	timeout := flag.Duration("scan-timeout", 15*time.Minute, "total job deadline including queue time")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected positional arguments")
	}
	scanner, err := scanjob.NewCLI(*binary)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	jobs, err := scanjob.New(ctx, scanner, *workers, *capacity, *timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer jobs.Close()
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Print(err)
		return
	}
	server := &http.Server{Handler: newRouter(jobs), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
	}()
	log.Printf("listening on %s", listener.Addr())
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Print(err)
	}
	stop()
	<-done
}

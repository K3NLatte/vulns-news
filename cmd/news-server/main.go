// Command news-server serves the real scan/analysis feed, or imports saved results offline.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vulns-news/server/live"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address; keep loopback (API is unauthenticated)")
	data := flag.String("data", ".local/news", "private persistent data directory; one server process only")
	frontend := flag.String("frontend", "frontend/dist", "built frontend directory; empty disables static files")
	model := flag.String("model", os.Getenv("OLLAMA_MODEL"), "Ollama model; empty serves saved data without starting new scans")
	baseURL := flag.String("base-url", os.Getenv("OLLAMA_BASE_URL"), "Ollama endpoint")
	workers := flag.Int("workers", 1, "concurrent scan/analysis jobs")
	capacity := flag.Int("capacity", 100, "maximum queued jobs")
	scan := flag.String("import-scan", "", "saved repo-scan JSON to import")
	analysis := flag.String("import-analysis", "", "matching analysis JSON to import without LLM calls")
	importOnly := flag.Bool("import-only", false, "validate/import and exit without listening")
	flag.Parse()
	if flag.NArg() != 0 || (*scan == "") != (*analysis == "") || (*importOnly && *scan == "") {
		log.Fatal("provide both import paths; positional arguments are unsupported")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg := live.Config{DataDir: *data, Model: *model, BaseURL: *baseURL, Workers: *workers, Capacity: *capacity}
	if *model != "" && !*importOnly {
		analyzer, err := live.NewAnalyzer(*model, *baseURL)
		if err != nil {
			log.Fatal(err)
		}
		cfg.Analyzer = analyzer
		log.Print("New scans contact GitHub and OSV; matched dependency/source/advisory evidence is sent to the configured Ollama endpoint. No LLM deadline is imposed.")
	}
	service, err := live.Open(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer service.Close()
	if *scan != "" {
		job, err := service.Import(*scan, *analysis)
		if err != nil {
			log.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(job); err != nil {
			log.Fatal(err)
		}
	}
	if *importOnly {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", service.Handler())
	if *frontend != "" {
		mux.Handle("/", http.FileServer(http.Dir(*frontend)))
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Print(err)
		return
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
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
	log.Printf("live feed listening on http://%s", listener.Addr())
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Print(err)
	}
	stop()
	<-done
}

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var version = "dev"

type Config struct {
	APIKey      string
	APIEmail    string
	APIToken    string
	Zones       []string
	Port        int
	ScrapeDelay int // seconds - how far back to query
	TopPaths    int // 0 disables per-path metrics
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		APIKey:      os.Getenv("CF_API_KEY"),
		APIEmail:    os.Getenv("CF_API_EMAIL"),
		APIToken:    os.Getenv("CF_API_TOKEN"),
		Port:        8080,
		ScrapeDelay: 300,
	}

	// Auth: either token or key+email
	if cfg.APIToken == "" && (cfg.APIKey == "" || cfg.APIEmail == "") {
		return nil, fmt.Errorf("set CF_API_TOKEN or both CF_API_KEY and CF_API_EMAIL")
	}

	// Zones
	zones := os.Getenv("CF_ZONES")
	if zones == "" {
		return nil, fmt.Errorf("CF_ZONES is required (comma-separated zone IDs)")
	}
	for _, z := range strings.Split(zones, ",") {
		z = strings.TrimSpace(z)
		if z != "" {
			cfg.Zones = append(cfg.Zones, z)
		}
	}
	if len(cfg.Zones) == 0 {
		return nil, fmt.Errorf("CF_ZONES must contain at least one zone ID")
	}

	// Optional port
	if p := os.Getenv("METRICS_PORT"); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("METRICS_PORT invalid: %w", err)
		}
		cfg.Port = port
	}

	// Optional scrape delay
	if d := os.Getenv("SCRAPE_DELAY"); d != "" {
		delay, err := strconv.Atoi(d)
		if err != nil {
			return nil, fmt.Errorf("SCRAPE_DELAY invalid: %w", err)
		}
		cfg.ScrapeDelay = delay
	}

	// Optional per-path metrics. Paths have unbounded cardinality, so this stays
	// off unless a limit is given.
	if t := os.Getenv("TOP_PATHS"); t != "" {
		top, err := strconv.Atoi(t)
		if err != nil {
			return nil, fmt.Errorf("TOP_PATHS invalid: %w", err)
		}
		if top < 0 {
			return nil, fmt.Errorf("TOP_PATHS must not be negative")
		}
		cfg.TopPaths = top
	}

	return cfg, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	log.Printf("cloudflare-exporter %s starting on :%d", version, cfg.Port)
	log.Printf("zones: %v, scrape_delay: %ds, top_paths: %d", cfg.Zones, cfg.ScrapeDelay, cfg.TopPaths)

	client := NewGraphQLClient(cfg)
	collector := NewCloudflareCollector(cfg, client)

	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: mux,
	}
	log.Fatal(server.ListenAndServe())
}

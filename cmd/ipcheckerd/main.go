package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/IliyaForsati/IP-Checker/internal/config"
)

func main() {
	configPath := flag.String("config", "/etc/ip-checker/config.json", "path to the JSON config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ipcheckerd: %v\n", err)
		os.Exit(1)
	}

	if _, err := cfg.BuildMatcher(); err != nil {
		fmt.Fprintf(os.Stderr, "ipcheckerd: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("config loaded: %s\n", *configPath)
	fmt.Printf("enforcement_mode: %s\n", cfg.EnforcementMode)
	fmt.Printf("cidr_sets: %d\n", len(cfg.CIDRSets))
	fmt.Printf("domains: %d\n", len(cfg.Domains))
	fmt.Printf("nfqueue: dns=%d tls=%d\n", cfg.NFQueue.DNSQueueNum, cfg.NFQueue.TLSQueueNum)
}

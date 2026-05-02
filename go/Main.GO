// SecureML — Go Network Security Scanner
// ========================================
// A concurrent TCP port scanner with service banner grabbing.
// Useful for network reconnaissance and attack-surface mapping.
//
// Usage:
//   go run main.go -host example.com -ports 1-1024 -workers 200 -timeout 2s
//
// ⚠  Only scan systems you own or have explicit written permission to test.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yourusername/secureml/scanner"
)

func main() {
	host    := flag.String("host",    "127.0.0.1", "Target host (IP or hostname)")
	portRange := flag.String("ports", "1-1024",    "Port range, e.g. 1-1024 or 22,80,443")
	workers := flag.Int("workers",   100,          "Concurrent scan workers")
	timeout := flag.Duration("timeout", 0,         "Per-port timeout (e.g. 2s). 0 = auto")
	output  := flag.String("output", "",           "Save results to file (optional)")
	verbose := flag.Bool("verbose",  false,        "Print closed ports too")
	flag.Parse()

	cfg := scanner.Config{
		Host:      *host,
		PortRange: *portRange,
		Workers:   *workers,
		Timeout:   *timeout,
		Verbose:   *verbose,
		OutputFile: *output,
	}

	if err := scanner.Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

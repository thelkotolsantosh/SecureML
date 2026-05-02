// Package scanner provides concurrent TCP port scanning with banner grabbing.
package scanner

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Well-Known Ports ───────────────────────────────────────────────────────────

var commonServices = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	6379:  "Redis",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	27017: "MongoDB",
}

// ── Types ──────────────────────────────────────────────────────────────────────

// Config holds all scan parameters.
type Config struct {
	Host       string
	PortRange  string
	Workers    int
	Timeout    time.Duration
	Verbose    bool
	OutputFile string
}

// Result describes a single port scan outcome.
type Result struct {
	Port    int
	Open    bool
	Service string
	Banner  string
	Latency time.Duration
}

func (r Result) String() string {
	state := "closed"
	if r.Open {
		state = "open  "
	}
	svc := r.Service
	if svc == "" {
		svc = "unknown"
	}
	line := fmt.Sprintf("  %-6d %-7s %-12s  %s", r.Port, state, svc, r.Banner)
	if r.Open {
		line += fmt.Sprintf("  [%v]", r.Latency.Round(time.Millisecond))
	}
	return strings.TrimRight(line, " ")
}

// ── Port Parsing ───────────────────────────────────────────────────────────────

// parsePorts converts a port specification string into a sorted slice of ints.
//
// Supported formats:
//   - "80"           single port
//   - "22,80,443"    comma-separated list
//   - "1-1024"       inclusive range
//   - "22,80,8000-8100" mixed
func parsePorts(spec string) ([]int, error) {
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid range: %q", part)
			}
			for p := lo; p <= hi; p++ {
				seen[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port: %q", part)
			}
			seen[p] = true
		}
	}

	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

// ── Banner Grabbing ────────────────────────────────────────────────────────────

// grabBanner attempts to read a service banner from an already-open connection.
// Returns an empty string if the service does not send a banner on connect.
func grabBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout / 2))
	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 80 {
			line = line[:80] + "…"
		}
		return line
	}
	return ""
}

// ── Single Port Scan ───────────────────────────────────────────────────────────

func scanPort(host string, port int, timeout time.Duration) Result {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, timeout)
	latency := time.Since(start)

	result := Result{
		Port:    port,
		Service: commonServices[port],
		Latency: latency,
	}

	if err != nil {
		return result // Open = false (zero value)
	}
	defer conn.Close()

	result.Open   = true
	result.Banner = grabBanner(conn, timeout)
	return result
}

// ── Worker Pool ────────────────────────────────────────────────────────────────

// Run executes the full scan described by cfg and prints / saves results.
func Run(cfg Config) error {
	// Resolve host
	ips, err := net.LookupHost(cfg.Host)
	if err != nil {
		return fmt.Errorf("cannot resolve host %q: %w", cfg.Host, err)
	}
	resolvedIP := ips[0]

	// Parse ports
	ports, err := parsePorts(cfg.PortRange)
	if err != nil {
		return err
	}

	// Auto timeout
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	total := len(ports)
	fmt.Printf("\n╔══════════════════════════════════════════════════╗\n")
	fmt.Printf("║       SecureML — TCP Port Scanner                ║\n")
	fmt.Printf("╚══════════════════════════════════════════════════╝\n")
	fmt.Printf("  Target   : %s (%s)\n", cfg.Host, resolvedIP)
	fmt.Printf("  Ports    : %s (%d total)\n", cfg.PortRange, total)
	fmt.Printf("  Workers  : %d\n", cfg.Workers)
	fmt.Printf("  Timeout  : %v\n", timeout)
	fmt.Printf("  Started  : %s\n\n", time.Now().Format(time.RFC1123))

	// Channel-based worker pool
	jobs    := make(chan int, total)
	results := make(chan Result, total)
	var wg sync.WaitGroup

	workers := cfg.Workers
	if workers > total {
		workers = total
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				results <- scanPort(resolvedIP, port, timeout)
			}
		}()
	}

	for _, p := range ports {
		jobs <- p
	}
	close(jobs)

	// Close results once all workers finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect
	all := make([]Result, 0, total)
	for r := range results {
		all = append(all, r)
	}

	// Sort by port
	sort.Slice(all, func(i, j int) bool { return all[i].Port < all[j].Port })

	// ── Print Summary ──────────────────────────────────────────────────────────
	var open []Result
	for _, r := range all {
		if r.Open {
			open = append(open, r)
		}
	}

	fmt.Printf("  %-6s %-7s %-12s  %-30s\n", "PORT", "STATE", "SERVICE", "BANNER")
	fmt.Println("  " + strings.Repeat("─", 64))

	for _, r := range all {
		if r.Open || cfg.Verbose {
			fmt.Println(r)
		}
	}

	fmt.Printf("\n  %d/%d ports open\n\n", len(open), total)

	// ── Optional file output ───────────────────────────────────────────────────
	if cfg.OutputFile != "" {
		if err := saveResults(cfg, all, resolvedIP); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save output: %v\n", err)
		} else {
			fmt.Printf("  Results saved → %s\n\n", cfg.OutputFile)
		}
	}

	return nil
}

func saveResults(cfg Config, results []Result, resolvedIP string) error {
	f, err := os.Create(cfg.OutputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "SecureML Port Scan Report\n")
	fmt.Fprintf(w, "Generated : %s\n", time.Now().Format(time.RFC1123))
	fmt.Fprintf(w, "Target    : %s (%s)\n", cfg.Host, resolvedIP)
	fmt.Fprintf(w, "Port Range: %s\n\n", cfg.PortRange)

	fmt.Fprintf(w, "%-6s %-7s %-12s  %s\n", "PORT", "STATE", "SERVICE", "BANNER")
	fmt.Fprintln(w, strings.Repeat("-", 70))

	for _, r := range results {
		if r.Open {
			svc := r.Service
			if svc == "" {
				svc = "unknown"
			}
			fmt.Fprintf(w, "%-6d %-7s %-12s  %s\n", r.Port, "open", svc, r.Banner)
		}
	}

	return w.Flush()
}

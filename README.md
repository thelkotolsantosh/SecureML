# 🔐 SecureML

> **Cybersecurity meets Data Science** — A dual-language toolkit combining Python-based ML anomaly detection with a Go network security scanner.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

---

## 📖 Overview

| Component | Language | Purpose |
|-----------|----------|---------|
| `python/anomaly_detection.py` | Python | ML-based network traffic anomaly detection using **Isolation Forest** |
| `go/main.go` + `go/scanner/` | Go | Concurrent **TCP port scanner** with banner grabbing |

The Python module tackles the **data science** side — training an unsupervised model on network flow features to detect DoS attacks, port scans, and data exfiltration. The Go tool handles the **offensive security** side — fast, concurrent port scanning useful for asset inventory and penetration testing recon.

---

## 🗂️ Repository Structure

```
SecureML/
├── python/
│   ├── anomaly_detection.py     # ML anomaly detector (Isolation Forest)
│   └── data/
│       └── sample_traffic.csv   # Auto-generated on first run
├── go/
│   ├── main.go                  # CLI entry point
│   ├── go.mod                   # Go module definition
│   └── scanner/
│       └── portscanner.go       # Core scanning logic
├── output/                      # Generated plots (git-ignored)
├── requirements.txt             # Python dependencies
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🚀 Quick Start

### Python — Anomaly Detection

#### 1. Prerequisites

- Python **3.10+**
- pip

#### 2. Install dependencies

```bash
pip install -r requirements.txt
```

#### 3. Run with synthetic data (no CSV needed)

```bash
cd SecureML
python python/anomaly_detection.py
```

#### 4. Run with your own CSV

Your CSV must contain these columns:
`packet_size`, `duration`, `bytes_sent`, `bytes_received`, `num_connections`, `port`

```bash
python python/anomaly_detection.py --input path/to/traffic.csv --output-dir output
```

#### 5. All flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | *(generate)* | Path to CSV input file |
| `--output-dir` | `output/` | Directory for plots |
| `--contamination` | `0.05` | Expected anomaly fraction |
| `--n-estimators` | `100` | Number of trees in IsolationForest |

#### Sample output

```
── Classification Report ──────────────────────────────
              precision    recall  f1-score   support

      Normal       0.99      0.98      0.99      1000
     Anomaly       0.84      0.92      0.88        50

    accuracy                           0.98      1050
```

Three plots are saved to `output/`:
- `scatter_anomaly.png` — Predicted vs true labels
- `score_distribution.png` — Anomaly score histogram
- `confusion_matrix.png` — Confusion matrix heatmap

---

### Go — Port Scanner

#### 1. Prerequisites

- Go **1.22+** — [Download](https://go.dev/dl/)

#### 2. Build

```bash
cd SecureML/go
go build -o secureml-scan .
```

#### 3. Run

```bash
# Scan localhost ports 1-1024
./secureml-scan -host 127.0.0.1 -ports 1-1024

# Scan specific ports on a target
./secureml-scan -host 192.168.1.1 -ports 22,80,443,3306,5432

# Save to file with verbose output
./secureml-scan -host example.com -ports 1-10000 -workers 500 -timeout 1s -output report.txt

# Or run without building
go run main.go -host 127.0.0.1 -ports 1-1024
```

#### 4. All flags

| Flag | Default | Description |
|------|---------|-------------|
| `-host` | `127.0.0.1` | Target IP or hostname |
| `-ports` | `1-1024` | Port range or list (e.g. `22,80,443` or `1-65535`) |
| `-workers` | `100` | Concurrent goroutines |
| `-timeout` | `2s` | Per-port dial timeout |
| `-output` | *(none)* | Save results to file |
| `-verbose` | `false` | Also print closed ports |

#### Sample output

```
╔══════════════════════════════════════════════════╗
║       SecureML — TCP Port Scanner                ║
╚══════════════════════════════════════════════════╝
  Target   : 192.168.1.1 (192.168.1.1)
  Ports    : 1-1024 (1024 total)
  Workers  : 100
  Timeout  : 2s

  PORT   STATE   SERVICE       BANNER
  ────────────────────────────────────────────────────────────────
  22     open    SSH           SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6  [18ms]
  80     open    HTTP                                                    [6ms]
  443    open    HTTPS                                                   [7ms]

  3/1024 ports open
```

---

## 🔬 How It Works

### Anomaly Detection (Python)

The detector uses **Isolation Forest**, an unsupervised algorithm that isolates observations by randomly partitioning features. Anomalies — which differ from the bulk of data — require fewer splits to isolate and receive higher anomaly scores.

**Features used:**

| Feature | Description |
|---------|-------------|
| `packet_size` | Average bytes per packet |
| `duration` | Session duration in seconds |
| `bytes_sent` | Total bytes sent in session |
| `bytes_received` | Total bytes received |
| `num_connections` | Connections within the session |
| `port` | Destination port number |

### Port Scanner (Go)

The scanner uses a **goroutine worker pool** — a fixed number of goroutines pull ports from a channel, attempt TCP dial, optionally grab a service banner, and push results back. This approach lets you saturate the network efficiently without spawning thousands of OS threads.

---

## ⚠️ Legal & Ethical Notice

> **The Go port scanner must only be run against systems you own or have explicit written authorization to test.** Unauthorized scanning may violate computer fraud laws in your jurisdiction (e.g., CFAA in the US, Computer Misuse Act in the UK). This tool is provided for educational purposes, CTF challenges, and legitimate penetration testing only.

---

## 🛠️ Development

### Run tests

```bash
# Python
python -m pytest python/tests/ -v

# Go
cd go && go test ./...
```

### Linting

```bash
# Python
pip install ruff && ruff check python/

# Go
go vet ./...
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "feat: add your feature"`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

Please follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgements

- [scikit-learn](https://scikit-learn.org/) — Machine learning in Python
- [Isolation Forest paper](https://cs.uts.edu.au/~qian/papers/iforest.pdf) — Liu, Ting & Zhou (2008)
- Go standard library `net` package for rock-solid networking primitives

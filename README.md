# ReconForge

![ReconForge Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

ReconForge is a modular, high-performance, asynchronous Python reconnaissance framework for Bug Bounty Hunters and Security Engineers.

It completely automates the attack surface mapping pipeline — from passive subdomain enumeration and DNS resolution to port scanning, HTTP probing, technology fingerprinting, and screenshot capture.

## Why ReconForge?

Many recon pipelines consist of brittle bash scripts chaining together various Golang tools via pipe operations. These scripts are difficult to maintain, fail unpredictably, and often lose data when an intermediate step crashes.

**ReconForge solves this by providing:**
- **Rock-solid State Management:** Every piece of data is instantly persisted to a local SQLite database. If a scan crashes or you stop it with `Ctrl+C`, you lose nothing.
- **Asynchronous Execution:** Built entirely on Python's `asyncio`, ReconForge can resolve thousands of DNS records and probe thousands of HTTP endpoints concurrently.
- **Stateless Plugin Architecture:** Easy to extend. The engine handles timeouts, concurrency limits, and retries — plugins just focus on returning data.
- **Professional Reporting:** Automatically correlates the raw data into a clean JSON API and a beautiful, shareable HTML report.

## Architecture

```mermaid
graph TD
    UI[CLI Interface] --> ORCH[Orchestrator]
    ORCH --> DB[(SQLite Database)]
    
    subgraph "Passive Stage"
        ORCH --> SUB[Subfinder Plugin]
        ORCH --> ASS[Assetfinder Plugin]
        ORCH --> AMA[Amass Plugin]
    end
    
    subgraph "Active Stage"
        ORCH --> DNS[aiodns Resolver]
        ORCH --> NAA[Naabu Plugin]
        ORCH --> HTT[HTTP Prober (aiohttp)]
        ORCH --> TEC[Tech Detector (httpx)]
        ORCH --> GOW[Gowitness Plugin]
    end
    
    ORCH --> COR[Asset Correlator]
    COR --> DB
    COR --> MOD[Normalized Asset Model]
    MOD --> REP[Report Exporter]
    REP --> HTM[HTML Report]
    REP --> JSO[JSON Report]
```

## Installation

ReconForge requires Python 3.12+.

```bash
git clone https://github.com/yourusername/ReconForge.git
cd ReconForge
pip install -e .
```

### External Dependencies

ReconForge integrates with best-in-class open-source tools. **ReconForge does not install these for you.** You must have the following binaries installed and available in your `$PATH` for the respective plugins to function:

- [Subfinder](https://github.com/projectdiscovery/subfinder) (Passive subdomains)
- [Assetfinder](https://github.com/tomnomnom/assetfinder) (Passive subdomains)
- [Amass](https://github.com/owasp-amass/amass) (Passive subdomains)
- [Naabu](https://github.com/projectdiscovery/naabu) (Fast port scanning)
- [Gowitness](https://github.com/sensepost/gowitness) (Screenshot capture)

*Note: The HTTP Prober, Tech Detector, and DNS Resolver are written purely in Python and require no external binaries.*

## Usage

### Quick Start
Scan a single target and generate reports:
```bash
recon scan example.com
```

Scan multiple targets from a file:
```bash
recon scan -f targets.txt
```

### Managing Reports
Reports are saved to the `reports/` directory by default. If you want to regenerate a report from existing scan data in your database without scanning the target again:
```bash
recon report example.com
```

### Checking Plugins
See which plugins are successfully loaded and have their required binaries in your `$PATH`:
```bash
recon plugins-list
```

## Disclaimer

**Authorized Use Only:** ReconForge is designed for security researchers, penetration testers, and bug bounty hunters to scan targets they have explicit authorization to test. You are solely responsible for your actions. Do not scan military, government, or critical infrastructure without written consent. The authors of ReconForge accept no liability for misuse.

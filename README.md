# ECLIPSE - Advanced Security Tool for Professionals

![ECLIPSE](main.png)

## Overview

**ECLIPSE** is a comprehensive, multi-purpose security toolkit designed for cybersecurity professionals, penetration testers, and ethical hackers. Built with **Go** for maximum speed, efficiency, and reliability, ECLIPSE combines multiple reconnaissance, exploitation, and analysis tools into a single, intuitive platform.

## Why Go?

ECLIPSE was developed in **Go** for several critical reasons:

- **⚡ Lightning-Fast Performance**: Go's compiled nature delivers native execution speed, crucial for processing large datasets and network operations
- **🔒 Memory Efficient**: Goroutines enable concurrent operations with minimal resource overhead
- **📦 Single Binary Distribution**: Cross-platform compilation produces standalone executables with zero dependencies
- **🛡️ Built-in Security**: Go's memory safety reduces vulnerabilities common in C/C++ tools
- **🚀 Enterprise-Grade Reliability**: Static typing and concurrency primitives ensure stable, predictable execution

## Features

ECLIPSE provides 20+ integrated security tools covering:

- **Network Reconnaissance**: IP scanning, port scanning, DNS/reverse DNS lookups
- **OSINT**: Open-source intelligence gathering with multiple data sources
- **Web Security**: ZPHISHER, Cookie Grabber, Phishing analysis
- **System Analysis**: PC utilities, Computer reports, Image analysis
- **Exploitation**: Ransomware simulation, Keylogger, SQL Injector, DDoS
- **Advanced Attacks**: RAT, Evil QR codes, Live camera hijacking
- **History & Reporting**: Comprehensive logging and historical analysis across all tools

## Installation

### Windows

```bash
# Download or clone the repository
git clone https://github.com/Edgar-GIT/ECLIPSE.git
cd ECLIPSE

# Ensure Go is installed (https://golang.org/dl)
go version

# Build the executable
go build -o programa.exe

# Run ECLIPSE
./programa.exe
```

### Linux/macOS

```bash
# Clone the repository
git clone https://github.com/Edgar-GIT/ECLIPSE.git
cd ECLIPSE

# Verify Go installation
go version

# Build the executable
go build -o programa

# Make it executable
chmod +x programa

# Run ECLIPSE
./programa
```

## Quick Start

1. **Run the program**:
   ```bash
   ./programa          # Linux/macOS
   programa.exe        # Windows
   ```

2. **Navigate the menu**:
   - Choose tool number [1-20]
   - Type `0` at any time to exit the program

3. **Access History & Reports**:
   - Select option `[7] - History Menu` to view all saved reports and analysis

## Available Tools

1. IP / Port Scanner
2. OSINT
3. PC Utilities
4. Password Cracker
5. DoS / DDoS
6. Image Analysis
7. History Menu
8. NetHunter
9. Cookie Grabber
10. Car Information
11. Phone Information
12. ZPHISHER
13. RAT
14. Ransomware
15. Keylogger
16. Garbage Injector
17. Live Camera Hijack
18. Evil QR
19. Web Inspection
20. Malware Obfuscator

### History Submenu Features

- View Computer Report
- View Scan Results (IP)
- View Port Scan Results
- View Website Report
- OSINT Statistics
- View Image History
- View Car History
- View Phone History
- Phishing History

## Requirements

- **Go 1.18+** (for building from source)
- **Windows 10+**, **Linux**, or **macOS**
- Internet connection for remote reconnaissance tools
- Standard system libraries

## Legal Notice

**ECLIPSE is designed exclusively for authorized security testing and educational purposes.**

This tool should only be used on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.

---

## Stay Ethical! 🛡️

Remember: With great power comes great responsibility. Use ECLIPSE responsibly and ethically.

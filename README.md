# C99 Shell Scanner

A comprehensive tool for detecting C99 web shells on target systems during ethical red team assessments and penetration testing in authorized lab environments.

## ⚠️ IMPORTANT DISCLAIMER

**This tool is intended ONLY for:**
- Authorized penetration testing
- Ethical red team exercises
- Security research in controlled lab environments
- Educational purposes with proper authorization

**DO NOT use this tool on systems you do not own or do not have explicit written permission to test.**

## 🚀 Features

- **Dual Language Support**: Python and PHP implementations
- **Multi-threaded Scanning**: Fast concurrent scanning capabilities
- **IP Range Support**: CIDR notation and individual IP scanning
- **Comprehensive Detection**: Multiple signature-based detection methods
- **Configurable Settings**: Customizable timeouts, threads, and detection thresholds
- **Output Logging**: JSON-formatted results with timestamps
- **Rate Limiting**: Built-in delays to avoid overwhelming target systems
- **SSL Support**: HTTPS scanning with certificate verification bypass for lab testing

## 📋 Requirements

### Python Version
- Python 3.6 or higher
- Required packages (install via `pip install -r requirements.txt`):
  - requests >= 2.28.0
  - urllib3 >= 1.26.0

### PHP Version
- PHP 7.4 or higher
- Required extensions:
  - php-curl
  - php-pcntl (for parallel processing)
  - php-json

## 🔧 Installation

1. **Clone or download the repository:**
```bash
git clone <repository-url>
cd c99-shell-scanner
```

2. **For Python version:**
```bash
pip install -r requirements.txt
```

3. **For PHP version (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install php-cli php-curl php-pcntl php-json
```

4. **Make scripts executable:**
```bash
chmod +x c99_scanner.py
chmod +x c99_scanner.php
```

## 📖 Usage Guide

### Python Scanner

#### Basic Usage
```bash
# Scan a single IP
python3 c99_scanner.py -t 192.168.1.100

# Scan an IP range (CIDR notation)
python3 c99_scanner.py -t 192.168.1.0/24

# Scan with custom ports
python3 c99_scanner.py -t 192.168.1.0/24 -p 80,443,8080,8443
```

#### Advanced Options
```bash
# Custom thread count and timeout
python3 c99_scanner.py -t 192.168.1.0/24 --threads 100 --timeout 15

# Save results to file
python3 c99_scanner.py -t 192.168.1.0/24 -o scan_results.txt

# Add delay between requests (stealth mode)
python3 c99_scanner.py -t 192.168.1.0/24 --delay 0.5

# Custom User-Agent
python3 c99_scanner.py -t 192.168.1.0/24 --user-agent "Mozilla/5.0 (Custom Scanner)"
```

#### Complete Example
```bash
python3 c99_scanner.py \
  --target 192.168.1.0/24 \
  --ports 80,443,8080,8443,3000,5000 \
  --threads 50 \
  --timeout 10 \
  --output results_$(date +%Y%m%d_%H%M%S).json \
  --delay 0.2
```

### PHP Scanner

#### Basic Usage
```bash
# Scan a single IP
php c99_scanner.php --target 192.168.1.100

# Scan an IP range
php c99_scanner.php --target 192.168.1.0/24

# Scan with custom ports
php c99_scanner.php --target 192.168.1.0/24 --ports 80,443,8080
```

#### Advanced Options
```bash
# Custom thread count and timeout
php c99_scanner.php --target 192.168.1.0/24 --threads 20 --timeout 15

# Save results to file
php c99_scanner.php --target 192.168.1.0/24 --output scan_results.txt

# Add delay between requests
php c99_scanner.php --target 192.168.1.0/24 --delay 0.5

# Custom User-Agent
php c99_scanner.php --target 192.168.1.0/24 --user-agent "Custom Scanner"
```

## 🎯 Common Scanning Scenarios

### 1. Quick Network Sweep
```bash
# Fast scan of common web ports
python3 c99_scanner.py -t 192.168.1.0/24 -p 80,443 --threads 100
```

### 2. Comprehensive Scan
```bash
# Detailed scan with all common ports
python3 c99_scanner.py -t 192.168.1.0/24 -p 80,443,8080,8443,3000,5000,8000,8888,9000 --threads 50 -o comprehensive_scan.json
```

### 3. Stealth Scan
```bash
# Slow scan with delays to avoid detection
python3 c99_scanner.py -t 192.168.1.0/24 --delay 1.0 --threads 10 --timeout 30
```

### 4. Single Host Deep Scan
```bash
# Thorough scan of a single target
python3 c99_scanner.py -t 192.168.1.50 -p 80,443,8080,8443,3000,5000,8000,8888,9000,10000 --timeout 20
```

### 5. Large Network Scan
```bash
# Scan multiple subnets efficiently
python3 c99_scanner.py -t 10.0.0.0/16 --threads 200 --timeout 5 -o large_network_scan.json
```

## 📊 Understanding Results

### Output Format
```json
{
  "url": "http://192.168.1.100:80/uploads/c99.php",
  "status_code": 200,
  "content_length": 15423,
  "signatures": ["c99shell", "eval(", "system(", "file_get_contents"],
  "confidence": 85,
  "response_time": 0.234,
  "headers": {
    "Content-Type": "text/html",
    "Server": "Apache/2.4.41"
  }
}
```

### Confidence Levels
- **90-100%**: Very likely C99 shell (multiple strong indicators)
- **70-89%**: Likely web shell (several indicators present)
- **50-69%**: Possible web shell (some indicators, needs manual verification)

## 🛠️ Configuration

### Custom Wordlists
Use the provided wordlists in the `wordlists/` directory:
- `c99_paths.txt`: Common shell paths and filenames
- `c99_signatures.txt`: Detection signatures and patterns

### Configuration File
Modify `config.json` to customize default settings:
```json
{
  "scanner_settings": {
    "default_threads": 50,
    "default_timeout": 10,
    "default_ports": [80, 443, 8080, 8443, 8000, 8888]
  }
}
```

## 🔍 Detection Methods

The scanner uses multiple detection techniques:

1. **Signature Analysis**: Searches for known C99 shell strings
2. **Function Detection**: Identifies dangerous PHP functions
3. **Interface Recognition**: Detects common shell interface elements
4. **Header Analysis**: Examines HTTP response headers
5. **Content Structure**: Analyzes page structure and layout

## 📝 Command Reference

### Python Scanner Options
```
-t, --target          Target IP or IP range (REQUIRED)
-p, --ports          Comma-separated ports (default: 80,443,8080,8443,8000,8888)
--threads            Number of threads (default: 50)
--timeout            Request timeout in seconds (default: 10)
--user-agent         Custom User-Agent string
-o, --output         Output file for results
--delay              Delay between requests in seconds (default: 0)
```

### PHP Scanner Options
```
--target             Target IP or IP range (REQUIRED)
--ports              Comma-separated ports (default: 80,443,8080,8443,8000,8888)
--threads            Number of threads (default: 20)
--timeout            Request timeout in seconds (default: 10)
--user-agent         Custom User-Agent string
--output             Output file for results
--delay              Delay between requests in seconds (default: 0)
--help               Show help message
```

## ⚡ Performance Tips

1. **Optimize Thread Count**: 
   - Small networks (< 50 hosts): 20-50 threads
   - Medium networks (50-200 hosts): 50-100 threads
   - Large networks (> 200 hosts): 100-200 threads

2. **Adjust Timeouts**:
   - Fast networks: 5-10 seconds
   - Slow networks: 15-30 seconds
   - Unreliable networks: 30+ seconds

3. **Use Delays for Stealth**:
   - No delay: Maximum speed
   - 0.1-0.5s: Moderate stealth
   - 1.0s+: High stealth

## 🔒 Security Considerations

### Lab Environment Setup
- Use isolated virtual machines
- Implement proper network segmentation
- Ensure no external network access
- Document all testing activities

### Responsible Usage
- Always obtain written authorization
- Follow responsible disclosure practices
- Respect rate limits and system resources
- Document findings professionally

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied (PHP)**
```bash
# Install required PHP extensions
sudo apt-get install php-pcntl php-curl
```

2. **SSL Certificate Errors**
```bash
# The scanner disables SSL verification for lab testing
# This is normal for self-signed certificates
```

3. **High Memory Usage**
```bash
# Reduce thread count for large scans
python3 c99_scanner.py -t 192.168.1.0/24 --threads 25
```

4. **Timeout Issues**
```bash
# Increase timeout for slow networks
python3 c99_scanner.py -t 192.168.1.0/24 --timeout 30
```

## 📈 Example Scan Reports

### Small Network Scan
```bash
python3 c99_scanner.py -t 192.168.1.0/24 -o small_network.json
```
Expected runtime: 2-5 minutes for /24 network

### Enterprise Network Scan
```bash
python3 c99_scanner.py -t 10.0.0.0/16 --threads 100 --timeout 5 -o enterprise.json
```
Expected runtime: 30-60 minutes for /16 network

## 📋 File Structure
```
c99-shell-scanner/
├── c99_scanner.py          # Python scanner
├── c99_scanner.php         # PHP scanner
├── config.json             # Configuration file
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── wordlists/
    ├── c99_paths.txt      # Common shell paths
    └── c99_signatures.txt # Detection signatures
```

## 🤝 Contributing

1. Test in isolated lab environments only
2. Follow responsible disclosure practices
3. Document any new detection methods
4. Ensure code works in both Python and PHP versions

## 📜 License

This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring compliance with local laws and regulations.

---

**Remember: Only use this tool in authorized environments with proper permission. Unauthorized scanning is illegal and unethical.**
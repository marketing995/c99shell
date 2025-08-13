# c99-style Web Shell Scanner (Defensive)

This tool is intended for ethical, defensive testing in lab environments or systems you are explicitly authorized to assess. It searches web targets for indicators of c99-variant PHP web shells and related backdoors using HTTP(S) requests and signature-based content analysis.

Do not use this tool on networks or systems you do not own or have written authorization to test.

## Features
- Concurrent scanning using Python standard library (ThreadPoolExecutor)
- Accepts CIDR ranges or host lists
- Optional port selection, default common HTTP(S) ports
- HTTP and HTTPS support, with optional TLS verification
- Signature-based content detection for known c99-like traits
- JSONL output for easy parsing
- No external Python dependencies

## Quick start
```
python /workspace/scanner.py --help
```

Optionally create a virtualenv if available, but it is not required.

## Usage examples
- Scan a list of hosts:
```
python /workspace/scanner.py --targets targets.txt --paths common --concurrency 200 --output findings.jsonl --only-http --timeout 6
```

- Scan a CIDR (confirm prompt required unless --i-understand is passed):
```
python /workspace/scanner.py --cidr 192.168.1.0/24 --paths common --concurrency 200 --output findings.jsonl --i-understand
```

- Custom paths and ports, ignore TLS errors, and verbose logging:
```
python /workspace/scanner.py --targets hosts.txt --paths /c99.php,/shell.php,/wso.php,/upload/cmd.php --ports 80,443,8080 --insecure --verbose
```

## Output
Each finding is a JSON object (one per line) with fields like:
```
{"target":"https://192.168.1.23:443/c99.php","status":200,"reason":"signature","matches":["c99shell","Safe mode Bypass"],"title":"c99shell v1.0"}
```

## Ethics and legal
- Only scan systems you own or are expressly authorized to test.
- Respect rate limits and avoid disruptive behavior.
- This tool is for defensive security; misuse may be illegal.

## Notes
- Signature rules are heuristics; false positives and false negatives are possible.
- Prefer placing lab targets in `targets.txt` or using a CIDR that maps to your lab segment.
- Consider adding authenticated checks and allowlists for production use.
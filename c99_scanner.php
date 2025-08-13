<?php
/**
 * C99 Shell Scanner - PHP Edition
 * Author: Security Research Tool
 * Purpose: Ethical red team testing and penetration testing in secured lab environments
 * 
 * Usage: php c99_scanner.php --target 192.168.1.0/24 --ports 80,443,8080
 */

class C99Scanner {
    private $threads;
    private $timeout;
    private $userAgent;
    private $outputFile;
    private $foundShells;
    private $delay;
    
    // Common C99 shell paths and filenames
    private $c99Paths = [
        'c99.php', 'shell.php', 'cmd.php', 'webshell.php', 'backdoor.php',
        'r57.php', 'wso.php', 'adminer.php', 'pma.php', 'admin.php',
        'uploads/c99.php', 'wp-content/c99.php', 'wp-content/uploads/c99.php',
        'images/c99.php', 'assets/c99.php', 'files/c99.php', 'tmp/c99.php',
        'temp/c99.php', 'cache/c99.php', 'backup/c99.php', 'test/c99.php',
        'includes/c99.php', 'admin/c99.php', 'administrator/c99.php',
        'wp-admin/c99.php', 'wp-includes/c99.php', 'modules/c99.php',
        'plugins/c99.php', 'components/c99.php', 'templates/c99.php',
        'themes/c99.php', 'css/c99.php', 'js/c99.php', 'fonts/c99.php',
        'data/c99.php', 'config/c99.php', 'logs/c99.php', 'var/c99.php',
        'usr/c99.php', 'home/c99.php', 'public/c99.php', 'private/c99.php',
        'secure/c99.php', 'protected/c99.php', 'restricted/c99.php',
        'hidden/c99.php', 'secret/c99.php', 'maintenance/c99.php',
        'dev/c99.php', 'development/c99.php', 'staging/c99.php',
        'demo/c99.php', 'old/c99.php', 'backup.php', 'db.php',
        'database.php', 'sql.php', 'mysql.php', 'connect.php',
        'connection.php', 'conf.php', 'configuration.php', 'settings.php',
        'setup.php', 'install.php', 'installer.php', 'update.php',
        'upgrade.php', 'migrate.php', 'import.php', 'export.php',
        'download.php', 'upload.php', 'file.php', 'files.php',
        'filemanager.php', 'fm.php', 'manager.php', 'control.php',
        'panel.php', 'cpanel.php', 'dashboard.php', 'index2.php',
        'home2.php', 'main2.php', 'default2.php', 'page.php',
        'content.php', 'view.php', 'show.php', 'display.php',
        'render.php', 'output.php', 'result.php', 'response.php'
    ];
    
    // C99 shell signatures for detection
    private $c99Signatures = [
        'c99shell', 'C99Shell', 'C99 Shell', 'c99 shell',
        'Orb Networks', 'SpiderLabs', 'Security team',
        'Safe-mode', 'eval(', 'system(', 'exec(',
        'shell_exec(', 'passthru(', 'file_get_contents',
        'fwrite(', 'fputs(', 'fopen(', 'readfile(',
        'move_uploaded_file', 'copy(', 'chmod(',
        'Server vars', 'PHP info', 'Eval PHP',
        'Execute', 'Command', 'Terminal',
        'File manager', 'Upload file', 'Download',
        'MySQL', 'Database', 'SQL query',
        'Back connect', 'Bind port', 'Reverse shell',
        'uname -a', 'id;', 'pwd;', 'ls -la',
        'cat /etc/passwd', 'whoami', 'ps aux',
        'netstat', 'ifconfig', 'route',
        '$_GET', '$_POST', '$_REQUEST',
        'base64_decode', 'gzinflate', 'str_rot13',
        'chr(', 'ord(', 'hexdec(',
        'Safe mode: OFF', 'Disable functions:'
    ];
    
    private $userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101'
    ];
    
    public function __construct($threads = 20, $timeout = 10, $userAgent = null, $outputFile = null, $delay = 0) {
        $this->threads = $threads;
        $this->timeout = $timeout;
        $this->userAgent = $userAgent ?: $this->userAgents[array_rand($this->userAgents)];
        $this->outputFile = $outputFile;
        $this->foundShells = [];
        $this->delay = $delay;
    }
    
    /**
     * Expand IP range/CIDR to individual IPs
     */
    public function expandIpRange($ipRange) {
        if (strpos($ipRange, '/') !== false) {
            list($ip, $prefix) = explode('/', $ipRange);
            $start = ip2long($ip);
            $end = $start + pow(2, 32 - $prefix) - 1;
            $ips = [];
            
            for ($i = $start + 1; $i < $end; $i++) {
                $ips[] = long2ip($i);
            }
            return $ips;
        } else {
            return [$ipRange];
        }
    }
    
    /**
     * Check if URL contains C99 shell
     */
    public function checkC99Shell($url) {
        $context = stream_context_create([
            'http' => [
                'timeout' => $this->timeout,
                'user_agent' => $this->userAgent,
                'ignore_errors' => true,
                'follow_location' => true,
                'max_redirects' => 3
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false
            ]
        ]);
        
        $startTime = microtime(true);
        $content = @file_get_contents($url, false, $context);
        $responseTime = microtime(true) - $startTime;
        
        if ($content === false) {
            return null;
        }
        
        $contentLower = strtolower($content);
        $foundSignatures = [];
        $confidence = 0;
        
        // Check for C99 signatures
        foreach ($this->c99Signatures as $signature) {
            if (strpos($contentLower, strtolower($signature)) !== false) {
                $foundSignatures[] = $signature;
            }
        }
        
        // Confidence scoring
        if (count($foundSignatures) >= 3) {
            $confidence += 30;
        }
        
        // Check for PHP code execution indicators
        $phpIndicators = ['<?php', '<?=', 'eval(', 'system(', 'exec('];
        $phpCount = 0;
        foreach ($phpIndicators as $indicator) {
            if (strpos($contentLower, $indicator) !== false) {
                $phpCount++;
            }
        }
        if ($phpCount >= 2) {
            $confidence += 25;
        }
        
        // Check for file operation indicators
        $fileOps = ['fopen(', 'fwrite(', 'file_get_contents', 'move_uploaded_file'];
        $fileCount = 0;
        foreach ($fileOps as $op) {
            if (strpos($contentLower, $op) !== false) {
                $fileCount++;
            }
        }
        if ($fileCount >= 2) {
            $confidence += 20;
        }
        
        // Check for shell command indicators
        $shellCmds = ['uname', 'whoami', 'pwd', 'ls -', 'cat /etc'];
        $shellCount = 0;
        foreach ($shellCmds as $cmd) {
            if (strpos($contentLower, $cmd) !== false) {
                $shellCount++;
            }
        }
        if ($shellCount >= 2) {
            $confidence += 25;
        }
        
        // HTTP response headers analysis
        if (isset($http_response_header)) {
            $statusCode = 200; // Default
            $headers = [];
            
            foreach ($http_response_header as $header) {
                if (strpos($header, 'HTTP/') === 0) {
                    preg_match('/HTTP\/\d\.\d\s+(\d+)/', $header, $matches);
                    if (isset($matches[1])) {
                        $statusCode = (int)$matches[1];
                    }
                } else {
                    $parts = explode(':', $header, 2);
                    if (count($parts) == 2) {
                        $headers[trim($parts[0])] = trim($parts[1]);
                    }
                }
            }
            
            if ($statusCode == 200) {
                if (isset($headers['Content-Type']) && strpos(strtolower($headers['Content-Type']), 'php') !== false) {
                    $confidence += 10;
                }
            }
        }
        
        // Determine if this is likely a C99 shell
        if ($confidence >= 50 || count($foundSignatures) >= 5) {
            return [
                'url' => $url,
                'status_code' => $statusCode ?? 200,
                'content_length' => strlen($content),
                'signatures' => $foundSignatures,
                'confidence' => $confidence,
                'response_time' => $responseTime,
                'headers' => $headers ?? []
            ];
        }
        
        return null;
    }
    
    /**
     * Scan a single host for C99 shells
     */
    public function scanHost($ip, $ports = [80, 443, 8080, 8443, 8000, 8888]) {
        $results = [];
        
        foreach ($ports as $port) {
            $schemes = ($port == 443 || $port == 8443) ? ['https'] : ['http'];
            if ($port == 80 || $port == 443) {
                $schemes = ['http', 'https'];
            }
            
            foreach ($schemes as $scheme) {
                $baseUrl = "$scheme://$ip:$port";
                
                foreach ($this->c99Paths as $path) {
                    $url = rtrim($baseUrl, '/') . '/' . ltrim($path, '/');
                    
                    if ($this->delay > 0) {
                        usleep($this->delay * 1000000);
                    }
                    
                    $result = $this->checkC99Shell($url);
                    
                    if ($result) {
                        $this->foundShells[] = $result;
                        echo "[+] FOUND: {$url} (Confidence: {$result['confidence']}%)\n";
                        echo "    Signatures: " . implode(', ', array_slice($result['signatures'], 0, 5)) . "\n";
                        
                        if ($this->outputFile) {
                            $this->saveResult($result);
                        }
                        
                        $results[] = $result;
                    }
                }
            }
        }
        
        return $results;
    }
    
    /**
     * Save result to output file
     */
    public function saveResult($result) {
        try {
            $timestamp = date('c');
            $line = $timestamp . ' - ' . json_encode($result) . "\n";
            file_put_contents($this->outputFile, $line, FILE_APPEND | LOCK_EX);
        } catch (Exception $e) {
            echo "Error saving result: " . $e->getMessage() . "\n";
        }
    }
    
    /**
     * Scan IP range for C99 shells
     */
    public function scanRange($ipRange, $ports = [80, 443, 8080, 8443, 8000, 8888]) {
        $ips = $this->expandIpRange($ipRange);
        
        echo "[*] Scanning " . count($ips) . " hosts for C99 shells...\n";
        echo "[*] Using {$this->threads} processes\n";
        echo "[*] Timeout: {$this->timeout}s\n";
        echo "[*] Ports: " . implode(', ', $ports) . "\n";
        echo str_repeat('-', 60) . "\n";
        
        $startTime = microtime(true);
        
        // Split IPs into chunks for parallel processing
        $chunks = array_chunk($ips, ceil(count($ips) / $this->threads));
        $processes = [];
        
        foreach ($chunks as $chunk) {
            $pid = pcntl_fork();
            
            if ($pid == -1) {
                die("Could not fork process\n");
            } elseif ($pid) {
                // Parent process
                $processes[] = $pid;
            } else {
                // Child process
                foreach ($chunk as $ip) {
                    $this->scanHost($ip, $ports);
                }
                exit(0);
            }
        }
        
        // Wait for all child processes to complete
        foreach ($processes as $pid) {
            pcntl_waitpid($pid, $status);
        }
        
        $endTime = microtime(true);
        $elapsed = $endTime - $startTime;
        
        echo str_repeat('-', 60) . "\n";
        echo "[*] Scan completed in " . number_format($elapsed, 2) . " seconds\n";
        echo "[*] Found " . count($this->foundShells) . " potential C99 shells\n";
        
        if (!empty($this->foundShells)) {
            echo "\n[+] Summary of findings:\n";
            foreach ($this->foundShells as $shell) {
                echo "    {$shell['url']} (Confidence: {$shell['confidence']}%)\n";
            }
        }
    }
}

/**
 * Display banner
 */
function displayBanner() {
    echo "
  ░█████╗░░█████╗░░█████╗░  ░██████╗░█████╗░░█████╗░███╗░░██╗███╗░░██╗███████╗██████╗░
  ██╔══██╗██╔══██╗██╔══██╗  ██╔════╝██╔══██╗██╔══██╗████╗░██║████╗░██║██╔════╝██╔══██╗
  ██║░░╚═╝╚██████║╚██████║  ╚█████╗░██║░░╚═╝███████║██╔██╗██║██╔██╗██║█████╗░░██████╔╝
  ██║░░██╗░╚═══██║░╚═══██║  ░╚═══██╗██║░░██╗██╔══██║██║╚████║██║╚████║██╔══╝░░██╔══██╗
  ╚█████╔╝░█████╔╝░█████╔╝  ██████╔╝╚█████╔╝██║░░██║██║░╚███║██║░╚███║███████╗██║░░██║
  ░╚════╝░░╚════╝░░╚════╝░  ╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝
    
    C99 Shell Scanner v1.0 - PHP Edition
    Ethical Red Team Testing Tool
    Use only in authorized lab environments!
    
";
}

/**
 * Display usage information
 */
function displayUsage() {
    echo "Usage: php c99_scanner.php [OPTIONS]\n\n";
    echo "Options:\n";
    echo "  --target <ip/range>     Target IP or IP range (CIDR notation) [REQUIRED]\n";
    echo "  --ports <ports>         Comma-separated list of ports (default: 80,443,8080,8443,8000,8888)\n";
    echo "  --threads <num>         Number of threads (default: 20)\n";
    echo "  --timeout <sec>         Request timeout in seconds (default: 10)\n";
    echo "  --user-agent <ua>       Custom User-Agent string\n";
    echo "  --output <file>         Output file for results\n";
    echo "  --delay <sec>           Delay between requests in seconds (default: 0)\n";
    echo "  --help                  Show this help message\n\n";
    echo "Examples:\n";
    echo "  php c99_scanner.php --target 192.168.1.0/24\n";
    echo "  php c99_scanner.php --target 10.0.0.1 --ports 80,443,8080 --threads 10\n";
    echo "  php c99_scanner.php --target 192.168.1.0/24 --output results.txt --delay 0.5\n\n";
}

/**
 * Parse command line arguments
 */
function parseArgs($argv) {
    $args = [];
    $count = count($argv);
    
    for ($i = 1; $i < $count; $i++) {
        if (strpos($argv[$i], '--') === 0) {
            $key = substr($argv[$i], 2);
            
            if ($i + 1 < $count && strpos($argv[$i + 1], '--') !== 0) {
                $args[$key] = $argv[$i + 1];
                $i++;
            } else {
                $args[$key] = true;
            }
        }
    }
    
    return $args;
}

/**
 * Main function
 */
function main($argv) {
    $args = parseArgs($argv);
    
    displayBanner();
    
    if (isset($args['help']) || !isset($args['target'])) {
        displayUsage();
        exit(0);
    }
    
    // Check for required extensions
    if (!extension_loaded('pcntl')) {
        echo "[!] Error: PCNTL extension is required for parallel processing\n";
        echo "[!] Install with: sudo apt-get install php-pcntl (Ubuntu/Debian)\n";
        exit(1);
    }
    
    $target = $args['target'];
    $ports = isset($args['ports']) ? array_map('intval', explode(',', $args['ports'])) : [80, 443, 8080, 8443, 8000, 8888];
    $threads = isset($args['threads']) ? (int)$args['threads'] : 20;
    $timeout = isset($args['timeout']) ? (int)$args['timeout'] : 10;
    $userAgent = isset($args['user-agent']) ? $args['user-agent'] : null;
    $outputFile = isset($args['output']) ? $args['output'] : null;
    $delay = isset($args['delay']) ? (float)$args['delay'] : 0;
    
    echo "[*] Target: $target\n";
    echo "[*] Ports: " . implode(', ', $ports) . "\n";
    echo "[*] Threads: $threads\n";
    echo "[*] Timeout: {$timeout}s\n";
    if ($outputFile) {
        echo "[*] Output: $outputFile\n";
    }
    if ($delay > 0) {
        echo "[*] Delay: {$delay}s\n";
    }
    echo "\n";
    
    // Initialize scanner
    $scanner = new C99Scanner($threads, $timeout, $userAgent, $outputFile, $delay);
    
    // Start scanning
    try {
        $scanner->scanRange($target, $ports);
    } catch (Exception $e) {
        echo "[!] Error: " . $e->getMessage() . "\n";
    }
}

// Run if called directly
if (basename(__FILE__) == basename($_SERVER['SCRIPT_NAME'])) {
    main($argv);
}
?>
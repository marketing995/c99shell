<?php
/**
 * Shared Hosting C99 Scanner
 * Optimized for cPanel and shared hosting environments
 */

class SharedHostingC99Scanner {
    private $config;
    private $foundShells;
    private $userAgent;
    
    // Reduced path list for shared hosting (to avoid timeouts)
    private $c99Paths = [
        'c99.php', 'shell.php', 'cmd.php', 'webshell.php', 'backdoor.php',
        'r57.php', 'wso.php', 'adminer.php', 'admin.php', 'manager.php',
        'uploads/c99.php', 'uploads/shell.php', 'uploads/cmd.php',
        'images/c99.php', 'images/shell.php', 'files/c99.php',
        'tmp/c99.php', 'temp/c99.php', 'cache/c99.php',
        'wp-content/c99.php', 'wp-content/uploads/c99.php',
        'wp-admin/c99.php', 'admin/c99.php', 'includes/c99.php',
        'data/c99.php', 'config/c99.php', 'backup/c99.php',
        'test/c99.php', 'dev/c99.php', 'old/c99.php'
    ];
    
    // Essential C99 signatures
    private $c99Signatures = [
        'c99shell', 'C99Shell', 'C99 Shell', 'eval(',
        'system(', 'exec(', 'shell_exec(', 'passthru(',
        'file_get_contents', 'fwrite(', 'Safe-mode',
        'Server vars', 'PHP info', 'Execute', 'Command',
        'File manager', 'Upload file', 'uname -a',
        'whoami', '$_GET', '$_POST', 'base64_decode'
    ];
    
    public function __construct($config) {
        $this->config = $config;
        $this->foundShells = [];
        $this->userAgent = 'Mozilla/5.0 (compatible; SecurityScanner/1.0)';
    }
    
    /**
     * Expand IP range for shared hosting (limited)
     */
    public function expandIpRange($ipRange) {
        if (strpos($ipRange, '/') !== false) {
            list($ip, $prefix) = explode('/', $ipRange);
            $prefix = (int)$prefix;
            
            // Limit range size for shared hosting
            if ($prefix < 24) {
                throw new Exception("IP range too large for shared hosting. Use /24 or smaller.");
            }
            
            $start = ip2long($ip);
            $end = $start + pow(2, 32 - $prefix) - 1;
            $ips = [];
            
            $count = 0;
            for ($i = $start + 1; $i < $end && $count < $this->config['max_hosts_per_scan']; $i++) {
                $ips[] = long2ip($i);
                $count++;
            }
            return $ips;
        } else {
            return [$ipRange];
        }
    }
    
    /**
     * Check if URL contains C99 shell (optimized for shared hosting)
     */
    public function checkC99Shell($url) {
        // Create context with shorter timeout for shared hosting
        $context = stream_context_create([
            'http' => [
                'timeout' => min($this->config['default_timeout'], 15),
                'user_agent' => $this->userAgent,
                'ignore_errors' => true,
                'follow_location' => false, // Disable redirects to save time
                'max_redirects' => 0
            ]
        ]);
        
        $startTime = microtime(true);
        $content = @file_get_contents($url, false, $context);
        $responseTime = microtime(true) - $startTime;
        
        if ($content === false || empty($content)) {
            return null;
        }
        
        // Limit content size to prevent memory issues
        if (strlen($content) > $this->config['max_response_size']) {
            $content = substr($content, 0, $this->config['max_response_size']);
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
        
        // Simplified confidence scoring
        if (count($foundSignatures) >= 2) {
            $confidence += $this->config['signature_weight'];
        }
        
        // Check for PHP indicators
        $phpIndicators = ['<?php', '<?=', 'eval(', 'system('];
        $phpCount = 0;
        foreach ($phpIndicators as $indicator) {
            if (strpos($contentLower, $indicator) !== false) {
                $phpCount++;
            }
        }
        if ($phpCount >= 2) {
            $confidence += $this->config['php_indicator_weight'];
        }
        
        // Check for file operations
        $fileOps = ['fopen(', 'fwrite(', 'file_get_contents', 'upload'];
        $fileCount = 0;
        foreach ($fileOps as $op) {
            if (strpos($contentLower, $op) !== false) {
                $fileCount++;
            }
        }
        if ($fileCount >= 1) {
            $confidence += $this->config['file_ops_weight'];
        }
        
        // Determine if this is likely a C99 shell
        if ($confidence >= $this->config['min_confidence_threshold'] || count($foundSignatures) >= 3) {
            return [
                'url' => $url,
                'status_code' => 200, // Simplified for shared hosting
                'content_length' => strlen($content),
                'signatures' => $foundSignatures,
                'confidence' => min($confidence, 100),
                'response_time' => $responseTime,
                'detected_at' => date('Y-m-d H:i:s')
            ];
        }
        
        return null;
    }
    
    /**
     * Scan single host (simplified for shared hosting)
     */
    public function scanHost($ip, $ports = null) {
        if ($ports === null) {
            $ports = $this->config['default_ports'];
        }
        
        $results = [];
        
        foreach ($ports as $port) {
            // Determine scheme
            $scheme = ($port == 443 || $port == 8443) ? 'https' : 'http';
            $baseUrl = "$scheme://$ip:$port";
            
            // Limit paths for shared hosting
            $pathsToCheck = array_slice($this->c99Paths, 0, $this->config['max_paths_per_scan']);
            
            foreach ($pathsToCheck as $path) {
                $url = rtrim($baseUrl, '/') . '/' . ltrim($path, '/');
                
                // Add delay for shared hosting
                if ($this->config['min_delay_between_requests'] > 0) {
                    usleep($this->config['min_delay_between_requests'] * 1000000);
                }
                
                $result = $this->checkC99Shell($url);
                
                if ($result) {
                    $this->foundShells[] = $result;
                    $results[] = $result;
                }
            }
        }
        
        return $results;
    }
    
    /**
     * Scan IP range (sequential for shared hosting)
     */
    public function scanRange($ipRange, $ports = null) {
        $ips = $this->expandIpRange($ipRange);
        $startTime = time();
        
        $scanData = [
            'scan_id' => uniqid('scan_', true),
            'target' => $ipRange,
            'start_time' => $startTime,
            'status' => 'running',
            'total_hosts' => count($ips),
            'scanned_hosts' => 0,
            'results' => [],
            'progress' => 0
        ];
        
        // Save initial scan data
        $this->saveScanData($scanData);
        
        try {
            // Sequential scanning for shared hosting
            foreach ($ips as $index => $ip) {
                // Check for timeout
                if (time() - $startTime > $this->config['max_scan_duration']) {
                    throw new Exception("Scan timeout exceeded");
                }
                
                $hostResults = $this->scanHost($ip, $ports);
                $scanData['results'] = array_merge($scanData['results'], $hostResults);
                $scanData['scanned_hosts'] = $index + 1;
                $scanData['progress'] = round((($index + 1) / count($ips)) * 100);
                
                // Update scan data
                $this->saveScanData($scanData);
                
                // Memory cleanup for shared hosting
                if (memory_get_usage() > 32 * 1024 * 1024) { // 32MB
                    gc_collect_cycles();
                }
            }
            
            $scanData['status'] = 'completed';
            $scanData['end_time'] = time();
            $scanData['duration'] = $scanData['end_time'] - $startTime;
            $scanData['total_shells_found'] = count($scanData['results']);
            
        } catch (Exception $e) {
            $scanData['status'] = 'error';
            $scanData['error'] = $e->getMessage();
        }
        
        // Save final scan data
        $this->saveScanData($scanData);
        
        return $scanData;
    }
    
    /**
     * Save scan data to file
     */
    private function saveScanData($scanData) {
        $filename = $this->config['scans_dir'] . '/' . $scanData['scan_id'] . '.json';
        file_put_contents($filename, json_encode($scanData, JSON_PRETTY_PRINT));
    }
    
    /**
     * Get scan data
     */
    public function getScanData($scanId) {
        $filename = $this->config['scans_dir'] . '/' . $scanId . '.json';
        if (file_exists($filename)) {
            return json_decode(file_get_contents($filename), true);
        }
        return null;
    }
    
    /**
     * Send simple email report (using PHP mail function)
     */
    public function sendEmailReport($scanData, $recipients) {
        if (!$this->config['email_enabled'] || empty($recipients)) {
            return false;
        }
        
        $subject = "C99 Shell Scanner Report - " . $scanData['target'];
        $shellCount = count($scanData['results']);
        
        $message = "C99 Shell Scanner Report\n";
        $message .= "========================\n\n";
        $message .= "Target: " . $scanData['target'] . "\n";
        $message .= "Scan Date: " . date('Y-m-d H:i:s', $scanData['start_time']) . "\n";
        $message .= "Duration: " . ($scanData['duration'] ?? 0) . " seconds\n";
        $message .= "Hosts Scanned: " . $scanData['total_hosts'] . "\n";
        $message .= "Shells Found: " . $shellCount . "\n\n";
        
        if ($shellCount > 0) {
            $message .= "DETECTED SHELLS:\n";
            $message .= "================\n";
            foreach ($scanData['results'] as $shell) {
                $message .= "URL: " . $shell['url'] . "\n";
                $message .= "Confidence: " . $shell['confidence'] . "%\n";
                $message .= "Signatures: " . implode(', ', array_slice($shell['signatures'], 0, 5)) . "\n";
                $message .= "---\n";
            }
        } else {
            $message .= "No C99 shells detected.\n";
        }
        
        $message .= "\nThis scan was performed for authorized security testing purposes only.\n";
        
        $headers = "From: " . $this->config['default_from_email'] . "\r\n";
        $headers .= "Reply-To: " . $this->config['default_from_email'] . "\r\n";
        $headers .= "X-Mailer: C99 Shell Scanner\r\n";
        
        $success = true;
        foreach ($recipients as $recipient) {
            if (!mail($recipient, $subject, $message, $headers)) {
                $success = false;
            }
        }
        
        return $success;
    }
}
?>
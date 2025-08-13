<?php
/**
 * C99 Shell Scanner - Background Worker
 * Handles scan execution in background process
 */

// Include the scanner class
require_once '../c99_scanner.php';

// Get scan ID from command line
if ($argc < 2) {
    die("Usage: php scanner_worker.php <scan_id>\n");
}

$scan_id = $argv[1];
$scan_file = "scans/$scan_id.json";

if (!file_exists($scan_file)) {
    die("Scan file not found: $scan_file\n");
}

// Load scan configuration
$scan_data = json_decode(file_get_contents($scan_file), true);

// Custom scanner class for web interface
class WebC99Scanner extends C99Scanner {
    private $scan_id;
    private $scan_file;
    
    public function __construct($scan_id, $scan_file, $threads = 20, $timeout = 10, $userAgent = null, $outputFile = null, $delay = 0, $emailConfig = null) {
        parent::__construct($threads, $timeout, $userAgent, $outputFile, $delay, $emailConfig);
        $this->scan_id = $scan_id;
        $this->scan_file = $scan_file;
    }
    
    public function updateScanProgress($results = null) {
        $scan_data = json_decode(file_get_contents($this->scan_file), true);
        
        if ($results !== null) {
            $scan_data['results'] = array_merge($scan_data['results'], $results);
        }
        
        $scan_data['last_update'] = time();
        file_put_contents($this->scan_file, json_encode($scan_data));
    }
    
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
                        $results[] = $result;
                        
                        // Update scan progress in real-time
                        $this->updateScanProgress([$result]);
                        
                        if ($this->outputFile) {
                            $this->saveResult($result);
                        }
                    }
                }
            }
        }
        
        return $results;
    }
    
    public function scanRange($ipRange, $ports = [80, 443, 8080, 8443, 8000, 8888]) {
        try {
            $ips = $this->expandIpRange($ipRange);
            $this->scanStartTime = microtime(true);
            $startTime = $this->scanStartTime;
            
            // Update status to running
            $scan_data = json_decode(file_get_contents($this->scan_file), true);
            $scan_data['status'] = 'running';
            $scan_data['total_hosts'] = count($ips);
            $scan_data['progress'] = 0;
            file_put_contents($this->scan_file, json_encode($scan_data));
            
            // For web interface, we'll scan sequentially to avoid overwhelming the server
            $scanned = 0;
            foreach ($ips as $ip) {
                $this->scanHost($ip, $ports);
                $scanned++;
                
                // Update progress
                $scan_data = json_decode(file_get_contents($this->scan_file), true);
                $scan_data['progress'] = round(($scanned / count($ips)) * 100);
                $scan_data['scanned_hosts'] = $scanned;
                file_put_contents($this->scan_file, json_encode($scan_data));
            }
            
            $endTime = microtime(true);
            $elapsed = $endTime - $startTime;
            
            // Update final status
            $scan_data = json_decode(file_get_contents($this->scan_file), true);
            $scan_data['status'] = 'completed';
            $scan_data['end_time'] = time();
            $scan_data['duration'] = $elapsed;
            $scan_data['total_shells_found'] = count($this->foundShells);
            file_put_contents($this->scan_file, json_encode($scan_data));
            
            // Send email report if configured
            if ($this->emailConfig) {
                $this->sendEmailReport($ipRange, $elapsed, count($ips));
            }
            
        } catch (Exception $e) {
            // Update status to error
            $scan_data = json_decode(file_get_contents($this->scan_file), true);
            $scan_data['status'] = 'error';
            $scan_data['error'] = $e->getMessage();
            file_put_contents($this->scan_file, json_encode($scan_data));
        }
    }
}

try {
    // Initialize scanner with web-specific configuration
    $scanner = new WebC99Scanner(
        $scan_id,
        $scan_file,
        $scan_data['threads'],
        $scan_data['timeout'],
        null, // user agent
        null, // output file (handled separately)
        $scan_data['delay'],
        $scan_data['email_config']
    );
    
    // Start scanning
    $scanner->scanRange($scan_data['target'], $scan_data['ports']);
    
} catch (Exception $e) {
    // Log error and update scan status
    error_log("Scanner worker error: " . $e->getMessage());
    
    $scan_data['status'] = 'error';
    $scan_data['error'] = $e->getMessage();
    file_put_contents($scan_file, json_encode($scan_data));
}
?>
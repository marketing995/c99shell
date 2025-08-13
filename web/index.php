<?php
/**
 * C99 Shell Scanner - Web Interface
 * Secure web-based scanner for authorized penetration testing
 */

// Security check - only allow access from authorized IPs (customize as needed)
$authorized_ips = [
    '127.0.0.1',
    '::1',
    // Add your lab IPs here
    // '192.168.1.0/24',
    // '10.0.0.0/8'
];

function is_authorized_ip($ip, $authorized_ranges) {
    foreach ($authorized_ranges as $range) {
        if (strpos($range, '/') !== false) {
            // CIDR notation
            list($subnet, $mask) = explode('/', $range);
            if ((ip2long($ip) & (~((1 << (32 - $mask)) - 1))) == ip2long($subnet)) {
                return true;
            }
        } else {
            // Single IP
            if ($ip === $range) {
                return true;
            }
        }
    }
    return false;
}

$client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
if (!is_authorized_ip($client_ip, $authorized_ips)) {
    http_response_code(403);
    die('Access denied. Unauthorized IP address.');
}

// Include the scanner class
require_once '../c99_scanner.php';

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    switch ($_POST['action']) {
        case 'scan':
            handle_scan_request();
            break;
        case 'get_status':
            handle_status_request();
            break;
        default:
            echo json_encode(['error' => 'Invalid action']);
    }
    exit;
}

function handle_scan_request() {
    $target = $_POST['target'] ?? '';
    $ports = array_map('intval', explode(',', $_POST['ports'] ?? '80,443,8080'));
    $threads = intval($_POST['threads'] ?? 20);
    $timeout = intval($_POST['timeout'] ?? 10);
    $delay = floatval($_POST['delay'] ?? 0);
    $email_to = $_POST['email_to'] ?? '';
    $email_from = $_POST['email_from'] ?? '';
    
    if (empty($target)) {
        echo json_encode(['error' => 'Target is required']);
        return;
    }
    
    // Validate target format
    if (!filter_var($target, FILTER_VALIDATE_IP) && !preg_match('/^\d+\.\d+\.\d+\.\d+\/\d+$/', $target)) {
        echo json_encode(['error' => 'Invalid target format. Use IP or CIDR notation.']);
        return;
    }
    
    // Setup email configuration
    $emailConfig = null;
    if (!empty($email_to) && !empty($email_from)) {
        $recipients = array_filter(array_map('trim', explode(',', $email_to)));
        if (!empty($recipients)) {
            $emailConfig = [
                'recipient_emails' => $recipients,
                'sender_email' => $email_from
            ];
        }
    }
    
    // Start scan in background
    $scan_id = uniqid('scan_', true);
    $scan_data = [
        'id' => $scan_id,
        'target' => $target,
        'ports' => $ports,
        'threads' => $threads,
        'timeout' => $timeout,
        'delay' => $delay,
        'email_config' => $emailConfig,
        'status' => 'running',
        'start_time' => time(),
        'results' => []
    ];
    
    // Save scan data
    file_put_contents("scans/$scan_id.json", json_encode($scan_data));
    
    // Start background process
    $cmd = sprintf(
        'php scanner_worker.php %s > /dev/null 2>&1 &',
        escapeshellarg($scan_id)
    );
    exec($cmd);
    
    echo json_encode(['success' => true, 'scan_id' => $scan_id]);
}

function handle_status_request() {
    $scan_id = $_POST['scan_id'] ?? '';
    
    if (empty($scan_id) || !file_exists("scans/$scan_id.json")) {
        echo json_encode(['error' => 'Invalid scan ID']);
        return;
    }
    
    $scan_data = json_decode(file_get_contents("scans/$scan_id.json"), true);
    echo json_encode($scan_data);
}

// Create scans directory if it doesn't exist
if (!file_exists('scans')) {
    mkdir('scans', 0755, true);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>C99 Shell Scanner - Web Interface</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 15px;
            margin: 20px;
            color: #856404;
        }
        
        .form-container {
            padding: 40px;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
            width: 100%;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .results-container {
            padding: 20px 40px 40px;
            border-top: 1px solid #e1e5e9;
            display: none;
        }
        
        .status {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 600;
        }
        
        .status.running {
            background: #e3f2fd;
            color: #1565c0;
            border: 1px solid #bbdefb;
        }
        
        .status.completed {
            background: #e8f5e8;
            color: #2e7d32;
            border: 1px solid #c8e6c9;
        }
        
        .status.error {
            background: #ffebee;
            color: #c62828;
            border: 1px solid #ffcdd2;
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e1e5e9;
            border-radius: 4px;
            overflow: hidden;
            margin: 15px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            width: 0%;
            transition: width 0.3s;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 0.6; }
            50% { opacity: 1; }
            100% { opacity: 0.6; }
        }
        
        .results-grid {
            display: grid;
            gap: 15px;
        }
        
        .result-item {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-left: 4px solid #ffc107;
            border-radius: 8px;
            padding: 15px;
        }
        
        .result-item.high-confidence {
            background: #ffebee;
            border-color: #f44336;
            border-left-color: #f44336;
        }
        
        .result-item.medium-confidence {
            background: #fff3e0;
            border-color: #ff9800;
            border-left-color: #ff9800;
        }
        
        .result-url {
            font-weight: 600;
            color: #333;
            margin-bottom: 10px;
            word-break: break-all;
        }
        
        .result-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            font-size: 14px;
            color: #666;
        }
        
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-right: 10px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .collapsible {
            background: #f8f9fa;
            border: 1px solid #e1e5e9;
            border-radius: 8px;
            margin-top: 20px;
        }
        
        .collapsible-header {
            padding: 15px;
            cursor: pointer;
            font-weight: 600;
            user-select: none;
        }
        
        .collapsible-content {
            padding: 0 15px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s;
        }
        
        .collapsible.active .collapsible-content {
            max-height: 300px;
            padding: 15px;
        }
        
        @media (max-width: 768px) {
            .form-row {
                grid-template-columns: 1fr;
            }
            
            .container {
                margin: 10px;
            }
            
            .form-container {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 C99 Shell Scanner</h1>
            <p>Web-based Security Assessment Tool</p>
        </div>
        
        <div class="warning">
            <strong>⚠️ SECURITY NOTICE:</strong> This tool is for authorized penetration testing only. 
            Use only on systems you own or have explicit written permission to test.
        </div>
        
        <div class="form-container">
            <form id="scanForm">
                <div class="form-group">
                    <label for="target">Target IP/Range *</label>
                    <input type="text" id="target" name="target" placeholder="192.168.1.0/24 or 192.168.1.100" required>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="ports">Ports</label>
                        <input type="text" id="ports" name="ports" value="80,443,8080,8443,8000,8888" placeholder="80,443,8080">
                    </div>
                    <div class="form-group">
                        <label for="threads">Threads</label>
                        <select id="threads" name="threads">
                            <option value="10">10 (Slow/Stealth)</option>
                            <option value="20" selected>20 (Normal)</option>
                            <option value="50">50 (Fast)</option>
                            <option value="100">100 (Very Fast)</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="timeout">Timeout (seconds)</label>
                        <input type="number" id="timeout" name="timeout" value="10" min="5" max="30">
                    </div>
                    <div class="form-group">
                        <label for="delay">Delay (seconds)</label>
                        <input type="number" id="delay" name="delay" value="0" min="0" max="5" step="0.1">
                    </div>
                </div>
                
                <div class="collapsible">
                    <div class="collapsible-header" onclick="toggleCollapsible(this)">
                        📧 Email Reporting (Optional) ▼
                    </div>
                    <div class="collapsible-content">
                        <div class="form-group">
                            <label for="email_to">Recipient Emails</label>
                            <input type="text" id="email_to" name="email_to" placeholder="admin@lab.com, security@lab.com">
                        </div>
                        <div class="form-group">
                            <label for="email_from">Sender Email</label>
                            <input type="email" id="email_from" name="email_from" placeholder="scanner@lab.com">
                        </div>
                    </div>
                </div>
                
                <div class="form-group" style="margin-top: 30px;">
                    <button type="submit" class="btn" id="scanBtn">
                        🚀 Start Scan
                    </button>
                </div>
            </form>
        </div>
        
        <div class="results-container" id="resultsContainer">
            <div class="status running" id="statusDiv">
                <span class="spinner"></span>
                <span id="statusText">Initializing scan...</span>
            </div>
            
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
            
            <div id="resultsContent"></div>
        </div>
    </div>

    <script>
        let currentScanId = null;
        let statusInterval = null;
        
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            startScan();
        });
        
        function toggleCollapsible(element) {
            element.parentNode.classList.toggle('active');
        }
        
        function startScan() {
            const formData = new FormData(document.getElementById('scanForm'));
            formData.append('action', 'scan');
            
            document.getElementById('scanBtn').disabled = true;
            document.getElementById('scanBtn').innerHTML = '<span class="spinner"></span> Starting...';
            document.getElementById('resultsContainer').style.display = 'block';
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    currentScanId = data.scan_id;
                    startStatusPolling();
                } else {
                    showError(data.error || 'Failed to start scan');
                }
            })
            .catch(error => {
                showError('Network error: ' + error.message);
            });
        }
        
        function startStatusPolling() {
            statusInterval = setInterval(checkStatus, 2000);
        }
        
        function checkStatus() {
            if (!currentScanId) return;
            
            const formData = new FormData();
            formData.append('action', 'get_status');
            formData.append('scan_id', currentScanId);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                updateStatus(data);
            })
            .catch(error => {
                console.error('Status check failed:', error);
            });
        }
        
        function updateStatus(data) {
            const statusDiv = document.getElementById('statusDiv');
            const statusText = document.getElementById('statusText');
            const resultsContent = document.getElementById('resultsContent');
            
            if (data.status === 'running') {
                statusText.textContent = `Scanning ${data.target}... (${data.results.length} shells found)`;
            } else if (data.status === 'completed') {
                clearInterval(statusInterval);
                
                statusDiv.className = 'status completed';
                statusDiv.innerHTML = `✅ Scan completed! Found ${data.results.length} potential shells`;
                
                document.getElementById('scanBtn').disabled = false;
                document.getElementById('scanBtn').innerHTML = '🚀 Start New Scan';
                
                displayResults(data.results);
            } else if (data.status === 'error') {
                clearInterval(statusInterval);
                showError(data.error || 'Scan failed');
            }
        }
        
        function displayResults(results) {
            const resultsContent = document.getElementById('resultsContent');
            
            if (results.length === 0) {
                resultsContent.innerHTML = '<div class="status completed">No C99 shells detected. Your systems appear clean!</div>';
                return;
            }
            
            let html = '<div class="results-grid">';
            
            results.forEach(result => {
                const confidenceClass = result.confidence >= 80 ? 'high-confidence' : 
                                      result.confidence >= 60 ? 'medium-confidence' : '';
                
                html += `
                    <div class="result-item ${confidenceClass}">
                        <div class="result-url">🚨 ${result.url}</div>
                        <div class="result-details">
                            <div><strong>Confidence:</strong> ${result.confidence}%</div>
                            <div><strong>Status:</strong> ${result.status_code}</div>
                            <div><strong>Size:</strong> ${result.content_length} bytes</div>
                            <div><strong>Response:</strong> ${result.response_time.toFixed(3)}s</div>
                            <div><strong>Signatures:</strong> ${result.signatures.slice(0, 3).join(', ')}</div>
                        </div>
                    </div>
                `;
            });
            
            html += '</div>';
            resultsContent.innerHTML = html;
        }
        
        function showError(message) {
            clearInterval(statusInterval);
            
            const statusDiv = document.getElementById('statusDiv');
            statusDiv.className = 'status error';
            statusDiv.innerHTML = `❌ Error: ${message}`;
            
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('scanBtn').innerHTML = '🚀 Start Scan';
        }
    </script>
</body>
</html>
<?php
/**
 * C99 Shell Scanner - Web Configuration
 * Configuration for cPanel/shared hosting deployment
 */

// SECURITY SETTINGS
// =================

// Authorized IP addresses (IMPORTANT: Configure this for your lab environment)
$config['authorized_ips'] = [
    '127.0.0.1',           // Localhost
    '::1',                 // IPv6 localhost
    // Add your lab/office IPs here:
    // '192.168.1.0/24',   // Local network
    // '10.0.0.0/8',       // Private network
    // '203.0.113.5',      // Your public IP
];

// Authentication (optional password protection)
$config['enable_password'] = false;  // Set to true to enable password protection
$config['password'] = 'lab_scanner_2024';  // Change this password!

// ACCESS CONTROL
// ==============

// Maximum concurrent scans
$config['max_concurrent_scans'] = 2;

// Maximum scan duration (seconds)
$config['max_scan_duration'] = 1800; // 30 minutes

// Maximum hosts per scan (to prevent resource abuse)
$config['max_hosts_per_scan'] = 256; // /24 network max

// Rate limiting
$config['min_delay_between_requests'] = 0.1; // Minimum delay in seconds
$config['max_threads'] = 10; // Maximum threads for shared hosting

// SCANNER SETTINGS
// ================

// Default scan settings
$config['default_ports'] = [80, 443, 8080, 8443, 8000, 8888];
$config['default_timeout'] = 10;
$config['default_threads'] = 5; // Conservative for shared hosting

// Paths and directories
$config['scans_dir'] = 'scans';
$config['logs_dir'] = 'logs';
$config['max_scan_history'] = 50; // Keep last 50 scans

// EMAIL SETTINGS
// ==============

// Email configuration for shared hosting
$config['email_enabled'] = true;
$config['smtp_enabled'] = false; // Most shared hosting doesn't allow SMTP

// Default from email (use your domain)
$config['default_from_email'] = 'scanner@' . $_SERVER['HTTP_HOST'];

// SHARED HOSTING OPTIMIZATIONS
// ============================

// Use file-based session storage instead of database
$config['session_storage'] = 'file';

// Disable parallel processing for shared hosting compatibility
$config['force_sequential_scanning'] = true;

// Reduced memory usage
$config['memory_limit'] = '128M';
$config['max_execution_time'] = 300; // 5 minutes per request

// File cleanup settings
$config['auto_cleanup_old_scans'] = true;
$config['cleanup_interval_hours'] = 24;
$config['keep_scans_for_days'] = 7;

// LOGGING
// =======

$config['enable_logging'] = true;
$config['log_level'] = 'INFO'; // DEBUG, INFO, WARNING, ERROR
$config['log_file'] = $config['logs_dir'] . '/scanner.log';
$config['max_log_size'] = 10485760; // 10MB

// SECURITY HEADERS
// ================

$config['security_headers'] = [
    'X-Frame-Options' => 'DENY',
    'X-Content-Type-Options' => 'nosniff',
    'X-XSS-Protection' => '1; mode=block',
    'Referrer-Policy' => 'strict-origin-when-cross-origin'
];

// DETECTION SETTINGS
// ==================

// Signature detection settings
$config['min_confidence_threshold'] = 50;
$config['signature_weight'] = 30;
$config['php_indicator_weight'] = 25;
$config['file_ops_weight'] = 20;
$config['shell_cmd_weight'] = 25;

// Response analysis
$config['analyze_response_headers'] = true;
$config['analyze_response_time'] = false; // Can be unreliable on shared hosting
$config['max_response_size'] = 1048576; // 1MB max response size

// WORDLISTS
// =========

// Custom wordlist settings
$config['use_custom_wordlists'] = true;
$config['max_paths_per_scan'] = 200; // Limit paths to avoid timeouts
$config['wordlist_file'] = '../wordlists/c99_paths.txt';

// INTERFACE SETTINGS
// ==================

// UI customization
$config['site_title'] = 'C99 Shell Scanner';
$config['theme_color'] = '#667eea';
$config['show_advanced_options'] = true;
$config['enable_scan_history'] = true;

// Results display
$config['results_per_page'] = 20;
$config['show_response_content'] = false; // Don't show full response content
$config['highlight_high_confidence'] = true;

// DEBUGGING
// =========

$config['debug_mode'] = false; // Set to true for development
$config['show_php_errors'] = false; // Only enable for debugging
$config['verbose_logging'] = false;

// CPANEL SPECIFIC SETTINGS
// =========================

// Common cPanel paths
$config['cpanel_detection'] = [
    'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? '',
    'is_cpanel' => (strpos($_SERVER['HTTP_HOST'] ?? '', 'cpanel') !== false),
    'shared_hosting' => true
];

// Resource limits for shared hosting
$config['resource_limits'] = [
    'max_memory_usage' => '64M',
    'max_cpu_time' => 30,
    'max_concurrent_connections' => 5
];

// HELPER FUNCTIONS
// ================

function isValidIP($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function isValidCIDR($cidr) {
    return preg_match('/^\d+\.\d+\.\d+\.\d+\/\d+$/', $cidr);
}

function getClientIP() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
    
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            if (strpos($ip, ',') !== false) {
                $ip = trim(explode(',', $ip)[0]);
            }
            if (isValidIP($ip)) {
                return $ip;
            }
        }
    }
    
    return '127.0.0.1';
}

function checkIPAuthorization($client_ip, $authorized_ranges) {
    foreach ($authorized_ranges as $range) {
        if (strpos($range, '/') !== false) {
            // CIDR notation
            list($subnet, $mask) = explode('/', $range);
            $subnet_long = ip2long($subnet);
            $ip_long = ip2long($client_ip);
            $mask_long = (-1 << (32 - (int)$mask));
            
            if (($ip_long & $mask_long) === ($subnet_long & $mask_long)) {
                return true;
            }
        } else {
            // Single IP
            if ($client_ip === $range) {
                return true;
            }
        }
    }
    return false;
}

// Initialize directories
function initializeDirectories($config) {
    $dirs = [$config['scans_dir'], $config['logs_dir']];
    
    foreach ($dirs as $dir) {
        if (!file_exists($dir)) {
            if (!mkdir($dir, 0755, true)) {
                error_log("Failed to create directory: $dir");
            }
        }
        
        // Create .htaccess to protect directories
        $htaccess_file = $dir . '/.htaccess';
        if (!file_exists($htaccess_file)) {
            file_put_contents($htaccess_file, "Order deny,allow\nDeny from all\n");
        }
    }
}

// Set security headers
function setSecurityHeaders($config) {
    foreach ($config['security_headers'] as $header => $value) {
        header("$header: $value");
    }
}

// Initialize configuration
initializeDirectories($config);

// Return configuration array
return $config;
?>
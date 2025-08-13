# C99 Shell Scanner - cPanel/Shared Hosting Deployment Guide

## 🚀 Quick Deployment for cPanel/Shared Hosting

This guide will help you deploy the C99 Shell Scanner on your cPanel hosting or shared hosting environment for authorized security testing in your lab.

## 📋 Prerequisites

- cPanel hosting account or shared hosting with PHP support
- PHP 7.4 or higher
- File Manager access or FTP access
- Your lab IP addresses for authorization

## 🔧 Installation Steps

### Step 1: Upload Files

1. **Using cPanel File Manager:**
   - Login to your cPanel
   - Open File Manager
   - Navigate to `public_html` or your domain folder
   - Create a new folder called `scanner` (or any name you prefer)
   - Upload all files from the `web/` directory to this folder

2. **Using FTP:**
   ```bash
   # Upload the web directory contents to your hosting
   ftp your-domain.com
   cd public_html/scanner
   # Upload all files from web/ directory
   ```

### Step 2: Configure Security

1. **Edit `config.php`:**
   ```php
   // Add your lab IP addresses
   $config['authorized_ips'] = [
       '127.0.0.1',
       'YOUR_LAB_IP_HERE',        // Replace with your IP
       '192.168.1.0/24',          // Your lab network
       // Add more IPs as needed
   ];
   
   // Enable password protection (recommended)
   $config['enable_password'] = true;
   $config['password'] = 'your_secure_password_here';
   ```

2. **Set file permissions:**
   ```bash
   # If using SSH/terminal access
   chmod 755 scanner/
   chmod 644 scanner/*.php
   chmod 755 scanner/scans/
   chmod 755 scanner/logs/
   ```

### Step 3: Test Installation

1. **Access the scanner:**
   ```
   https://yourdomain.com/scanner/
   ```

2. **Verify security:**
   - Test IP authorization
   - Test password protection (if enabled)
   - Check that unauthorized IPs are blocked

### Step 4: Configure Email Reports

1. **Edit email settings in `config.php`:**
   ```php
   $config['email_enabled'] = true;
   $config['default_from_email'] = 'scanner@yourdomain.com';
   ```

2. **Test email functionality:**
   - Run a small scan with email reporting
   - Check if emails are delivered correctly

## 🔒 Security Configuration

### IP Authorization Setup

```php
// Example configurations for different scenarios:

// Single office IP
$config['authorized_ips'] = ['203.0.113.5'];

// Office network range
$config['authorized_ips'] = ['192.168.1.0/24'];

// Multiple locations
$config['authorized_ips'] = [
    '203.0.113.5',      // Office IP
    '198.51.100.10',    // Home IP
    '10.0.0.0/8',       // VPN range
];

// Dynamic IP with password protection
$config['authorized_ips'] = ['0.0.0.0/0']; // Allow all IPs
$config['enable_password'] = true;         // But require password
```

### Password Protection

```php
// Enable password protection
$config['enable_password'] = true;
$config['password'] = 'Lab_Scanner_2024!';

// Users will see a login form before accessing the scanner
```

### File Protection

Create `.htaccess` files to protect sensitive directories:

```apache
# In scans/ directory
Order deny,allow
Deny from all

# In logs/ directory  
Order deny,allow
Deny from all
```

## 📊 Usage Examples

### Basic Scan
```
Target: 192.168.1.0/24
Ports: 80,443,8080
Threads: 5 (recommended for shared hosting)
```

### Stealth Scan
```
Target: 192.168.1.0/24
Ports: 80,443
Threads: 2
Delay: 0.5 seconds
```

### Comprehensive Scan
```
Target: 192.168.1.50
Ports: 80,443,8080,8443,8000,8888,3000,5000
Threads: 5
Email: admin@lab.com
```

## ⚡ Performance Optimization for Shared Hosting

### Recommended Settings

```php
// config.php optimizations
$config['default_threads'] = 5;           // Conservative threading
$config['max_hosts_per_scan'] = 64;       // Limit scan size
$config['min_delay_between_requests'] = 0.2; // Rate limiting
$config['max_execution_time'] = 300;      // 5 minutes max
$config['memory_limit'] = '128M';         // Memory limit
```

### Avoid Timeouts

1. **Scan smaller ranges:** Use /26 or /27 instead of /24
2. **Use delays:** Add 0.1-0.5 second delays between requests
3. **Reduce paths:** Limit to essential paths only
4. **Monitor resources:** Check hosting resource usage

## 🔍 Troubleshooting

### Common Issues

1. **"Access Denied" Error:**
   ```
   Solution: Add your IP to authorized_ips in config.php
   Check your public IP: https://whatismyip.com
   ```

2. **Scan Timeouts:**
   ```
   Solution: Reduce scan size or add delays
   Use smaller IP ranges (/26 instead of /24)
   Increase max_execution_time in config.php
   ```

3. **Memory Errors:**
   ```
   Solution: Reduce memory usage
   Lower max_paths_per_scan
   Increase min_delay_between_requests
   ```

4. **Email Not Working:**
   ```
   Solution: Check hosting email settings
   Verify from_email uses your domain
   Contact hosting support about mail() function
   ```

### Hosting-Specific Notes

#### cPanel Shared Hosting
- Usually supports PHP mail() function
- May have execution time limits (300 seconds)
- Memory limits typically 128MB-256MB
- Some hosts block outbound connections

#### Popular Hosting Providers

**Hostgator/Bluehost:**
```php
$config['memory_limit'] = '128M';
$config['max_execution_time'] = 300;
$config['default_threads'] = 3;
```

**SiteGround:**
```php
$config['memory_limit'] = '256M';
$config['max_execution_time'] = 300;
$config['default_threads'] = 5;
```

**GoDaddy:**
```php
$config['memory_limit'] = '128M';
$config['max_execution_time'] = 120;
$config['default_threads'] = 2;
```

## 📁 File Structure After Deployment

```
public_html/scanner/
├── index.php              # Main interface
├── config.php             # Configuration
├── shared_hosting_scanner.php # Scanner engine
├── scans/                  # Scan results (protected)
│   ├── .htaccess
│   └── scan_*.json
├── logs/                   # Log files (protected)
│   ├── .htaccess
│   └── scanner.log
└── wordlists/              # Optional wordlists
    └── c99_paths.txt
```

## 🌐 Access URLs

After deployment, access your scanner at:
- **Main Interface:** `https://yourdomain.com/scanner/`
- **Direct Scan:** `https://yourdomain.com/scanner/?action=scan`

## 🔐 Security Best Practices

1. **Use HTTPS:** Ensure your domain has SSL certificate
2. **Regular Updates:** Keep the scanner files updated
3. **Monitor Logs:** Check logs regularly for unauthorized access
4. **Backup Configs:** Keep backup of configuration files
5. **Clean Old Scans:** Regularly clean old scan files

## 📞 Support

If you encounter issues:

1. **Check Logs:** Look in `logs/scanner.log`
2. **Test PHP:** Verify PHP version and extensions
3. **Contact Host:** Some hosts have specific limitations
4. **Debug Mode:** Enable debug mode in config.php for development

## ⚠️ Legal Disclaimer

**IMPORTANT:** Only use this tool on systems you own or have explicit written permission to test. Unauthorized scanning is illegal and may violate terms of service.

---

**Your scanner is now ready for authorized security testing in your lab environment!**
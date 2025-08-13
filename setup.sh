#!/bin/bash

echo "🔧 C99 Shell Scanner Setup"
echo "=========================="

# Make scripts executable
echo "Making scripts executable..."
chmod +x c99_scanner.py
chmod +x c99_scanner.php

# Check Python
echo "Checking Python installation..."
if command -v python3 &> /dev/null; then
    echo "✅ Python3 found: $(python3 --version)"
    
    # Install Python dependencies
    echo "Installing Python dependencies..."
    pip install -r requirements.txt
    echo "✅ Python dependencies installed"
else
    echo "❌ Python3 not found. Please install Python 3.6+"
fi

# Check PHP
echo "Checking PHP installation..."
if command -v php &> /dev/null; then
    echo "✅ PHP found: $(php --version | head -1)"
    
    # Check PHP extensions
    echo "Checking PHP extensions..."
    php -m | grep -E "(curl|pcntl|json)" > /dev/null
    if [ $? -eq 0 ]; then
        echo "✅ Required PHP extensions found"
    else
        echo "⚠️  Some PHP extensions may be missing"
        echo "Install with: sudo apt-get install php-curl php-pcntl php-json"
    fi
else
    echo "❌ PHP not found. Install with: sudo apt-get install php-cli"
fi

echo ""
echo "🎯 Quick Test Commands:"
echo "python3 c99_scanner.py --help"
echo "php c99_scanner.php --help"
echo ""
echo "📖 Read the README.md file for complete usage instructions"
echo "✅ Setup complete!"
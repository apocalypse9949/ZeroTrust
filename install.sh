#!/bin/bash

# ZeroTrustScope Installation Script
# This script installs dependencies and builds the ZeroTrustScope system

set -e

echo "=== ZeroTrustScope Installation ==="
echo

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "This script should not be run as root for dependency installation."
   echo "Please run as a regular user and use sudo when prompted."
   exit 1
fi

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo "Cannot detect OS. Please install dependencies manually."
    exit 1
fi

echo "Detected OS: $OS $VER"
echo

# Install system dependencies
echo "Installing system dependencies..."

if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    sudo apt-get update
    sudo apt-get install -y build-essential libpcap-dev ruby-dev ruby-bundler
elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]]; then
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y libpcap-devel ruby-devel
    # Install bundler if not available
    if ! command -v bundle &> /dev/null; then
        sudo gem install bundler
    fi
elif [[ "$OS" == *"Fedora"* ]]; then
    sudo dnf groupinstall -y "Development Tools"
    sudo dnf install -y libpcap-devel ruby-devel
    if ! command -v bundle &> /dev/null; then
        sudo gem install bundler
    fi
else
    echo "Unsupported OS: $OS"
    echo "Please install the following packages manually:"
    echo "- build-essential (or equivalent)"
    echo "- libpcap-dev (or equivalent)"
    echo "- ruby-dev (or equivalent)"
    echo "- ruby-bundler (or equivalent)"
    exit 1
fi

echo "System dependencies installed successfully."
echo

# Check Ruby version
RUBY_VERSION=$(ruby -e "puts RUBY_VERSION")
echo "Ruby version: $RUBY_VERSION"

if [[ $(echo "$RUBY_VERSION 2.7" | tr " " "\n" | sort -V | head -n 1) != "2.7" ]]; then
    echo "Warning: Ruby 2.7+ is recommended. Current version: $RUBY_VERSION"
fi

echo

# Install Ruby gems
echo "Installing Ruby gems..."
bundle install
echo "Ruby gems installed successfully."
echo

# Build C components
echo "Building C components..."
make clean
make
echo "C components built successfully."
echo

# Create log file
touch zerotrust_log.json
chmod 644 zerotrust_log.json

echo "=== Installation Complete ==="
echo
echo "ZeroTrustScope has been installed successfully!"
echo
echo "Next steps:"
echo "1. Add trusted IP addresses:"
echo "   ruby zerotrust_scope.rb trust <IP_ADDRESS>"
echo
echo "2. Start monitoring (requires root):"
echo "   sudo ruby zerotrust_scope.rb start"
echo
echo "3. Or start the web dashboard:"
echo "   ruby web_ui.rb"
echo
echo "For more information, see README.md"
echo 
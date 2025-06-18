# ZeroTrustScope

A modular security enforcement tool designed for edge and IoT environments, implementing Zero Trust principles: deny by default, allow by explicit trust.

## Features

- **Real-time Network Traffic Capture**: Uses libpcap to capture and analyze network packets
- **Zero Trust Enforcement**: Denies all traffic by default, only allows explicitly trusted sources
- **Dynamic Firewall Rules**: Automatically blocks unknown IP addresses using iptables
- **Ruby Integration**: FFI-based interface for scripting and dynamic rule control
- **Web Dashboard**: Modern Sinatra-based web UI for monitoring and control
- **CLI Interface**: Thor-based command-line interface for system administration
- **JSON Logging**: Structured logging for integration with monitoring systems
- **Lightweight**: Designed for Linux-based IoT and embedded systems

## Architecture

- **C Core Engine**: High-performance packet capture and analysis
- **Ruby Interface**: Dynamic policy management and user interfaces
- **FFI Bridge**: Seamless integration between C and Ruby components

## Prerequisites

### System Requirements
- Linux-based system (tested on Ubuntu 20.04+)
- Root privileges (for packet capture and iptables)
- libpcap development libraries
- Ruby 2.7+ with development headers

### Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential libpcap-dev ruby-dev

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install libpcap-devel ruby-devel

# Install Ruby gems
bundle install
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd ZeroTrust
   ```

2. **Compile the C components**:
   ```bash
   make clean
   make
   ```

3. **Install Ruby dependencies**:
   ```bash
   bundle install
   ```

4. **Set up initial trusted IPs** (optional):
   ```bash
   # Add your local network gateway
   ruby zerotrust_scope.rb trust 192.168.1.1
   ```

## Usage

### Command Line Interface

```bash
# Start network monitoring
ruby zerotrust_scope.rb start

# Add a trusted IP address
ruby zerotrust_scope.rb trust 192.168.1.100

# Block an IP address
ruby zerotrust_scope.rb block 10.0.0.50

# View real-time logs
ruby zerotrust_scope.rb logs
```

### Web Dashboard

```bash
# Start the web interface
ruby web_ui.rb
```

Then open your browser to `http://localhost:4567`

### Programmatic Usage

```ruby
require_relative 'zerotrust_scope'

# Start monitoring
ZeroTrustScope.start_monitoring

# Add trusted IP
ZeroTrustScope.add_trusted_ip("192.168.1.100")

# Block IP
ZeroTrustScope.block_untrusted_ip("10.0.0.50")
```

## Configuration

### Network Interface
Edit `src/capture.c` to change the default network interface:
```c
pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
```

### Trusted IPs
The system maintains a list of trusted IP addresses in memory. Add them via:
- CLI: `ruby zerotrust_scope.rb trust <IP>`
- Web UI: Use the "Trust IP" button
- Programmatically: `ZeroTrustScope.add_trusted_ip(<IP>)`

### Logging
Security events are logged to `zerotrust_log.json` in JSON format:
```json
{
  "timestamp": "2024-01-15 14:30:25",
  "event_type": "ALERT",
  "description": "Unknown source IP detected"
}
```

## Security Features

### Packet Analysis
- **IP Address Validation**: Checks source IPs against trusted list
- **Protocol Detection**: Identifies IP, TCP, UDP packets
- **Real-time Blocking**: Automatically blocks unknown sources

### Firewall Integration
- **iptables Rules**: Dynamic rule creation and management
- **Automatic Blocking**: Unknown IPs are blocked immediately
- **Rule Persistence**: Rules persist until system restart

### Logging and Monitoring
- **Structured Logs**: JSON-formatted for easy parsing
- **Real-time Alerts**: Immediate notification of security events
- **Audit Trail**: Complete record of all security decisions

## Development

### Project Structure
```
ZeroTrust/
├── src/
│   ├── main.c          # Main application entry point
│   ├── capture.c       # Packet capture using libpcap
│   ├── capture.h       # Capture function declarations
│   ├── policy.c        # Security policy enforcement
│   ├── policy.h        # Policy function declarations
│   └── ffi_interface.c # FFI wrapper functions
├── zerotrust_scope.rb  # Ruby CLI interface
├── web_ui.rb          # Sinatra web dashboard
├── Gemfile            # Ruby dependencies
├── Makefile           # C compilation rules
└── README.md          # This file
```

### Building from Source
```bash
# Clean previous builds
make clean

# Compile C components
make

# Install Ruby dependencies
bundle install
```

### Testing
```bash
# Test packet capture (requires root)
sudo ruby zerotrust_scope.rb start

# Test web interface
ruby web_ui.rb
```

## Troubleshooting

### Common Issues

1. **Permission Denied**:
   ```bash
   sudo ruby zerotrust_scope.rb start
   ```

2. **Interface Not Found**:
   - Check available interfaces: `ip addr show`
   - Update interface name in `src/capture.c`

3. **libpcap Not Found**:
   ```bash
   sudo apt-get install libpcap-dev
   ```

4. **Ruby FFI Errors**:
   ```bash
   bundle install
   ```

### Debug Mode
Enable verbose logging by modifying the C source files to include more detailed output.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Considerations

- **Root Access Required**: The tool requires root privileges for packet capture and firewall management
- **Network Impact**: Incorrect configuration may block legitimate traffic
- **Resource Usage**: Continuous packet capture may impact system performance
- **Log Security**: Ensure log files are properly secured and rotated

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs in `zerotrust_log.json`
3. Open an issue on the project repository 
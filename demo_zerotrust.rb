#!/usr/bin/env ruby

require 'json'
require 'fileutils'
require 'time'

# Load the ZeroTrustScope module
begin
  require_relative 'zerotrust_scope'
  FFI_AVAILABLE = true
rescue LoadError => e
  puts "Warning: Could not load zerotrust_scope module: #{e.message}"
  puts "Using Ruby stub implementation for demo..."
  FFI_AVAILABLE = false
  require_relative 'zerotrust_stub'
end

class ZeroTrustDemo
  def initialize
    @trusted_ips = []
    @blocked_ips = []
    @demo_log = []
  end

  def run_demo
    puts "=== ZeroTrustScope Demo ==="
    puts "This demo shows the basic functionality of ZeroTrustScope"
    puts
    
    # Demo 1: System initialization
    demo_system_init
    
    # Demo 2: Adding trusted IPs
    demo_add_trusted_ips
    
    # Demo 3: Blocking malicious IPs
    demo_block_malicious_ips
    
    # Demo 4: Network monitoring simulation
    demo_network_monitoring
    
    # Demo 5: Security incident response
    demo_security_incident
    
    # Demo 6: Log analysis
    demo_log_analysis
    
    puts
    puts "=== Demo Complete ==="
    puts "ZeroTrustScope is ready for production use!"
  end

  private

  def demo_system_init
    puts "1. System Initialization"
    puts "   Initializing ZeroTrustScope security system..."
    sleep 1
    
    # Load configuration
    config = load_config
    if config
      puts "   ✓ Configuration loaded successfully"
    else
      puts "   ⚠ Using default configuration"
    end
    
    # Initialize trusted IPs
    @trusted_ips = ["192.168.1.100", "10.0.0.50"]
    puts "   ✓ Trusted IPs initialized: #{@trusted_ips.join(', ')}"
    
    # Initialize blocked IPs
    @blocked_ips = ["203.0.113.45"]
    puts "   ✓ Blocked IPs initialized: #{@blocked_ips.join(', ')}"
    
    puts "   System ready for operation!"
    puts
  end

  def demo_add_trusted_ips
    puts "2. Adding Trusted IP Addresses"
    puts "   Demonstrating how to add trusted IPs to the system..."
    
    new_trusted_ips = ["192.168.1.200", "172.16.0.10"]
    
    new_trusted_ips.each do |ip|
      puts "   Adding #{ip} to trusted list..."
      add_trusted_ip(ip)
      sleep 0.5
    end
    
    puts "   ✓ Trusted IP management complete"
    puts
  end

  def demo_block_malicious_ips
    puts "3. Blocking Malicious IP Addresses"
    puts "   Demonstrating threat response capabilities..."
    
    malicious_ips = ["198.51.100.123", "203.0.113.100"]
    
    malicious_ips.each do |ip|
      puts "   Blocking malicious IP #{ip}..."
      block_ip(ip)
      sleep 0.5
    end
    
    puts "   ✓ Threat blocking complete"
    puts
  end

  def demo_network_monitoring
    puts "4. Network Monitoring Simulation"
    puts "   Simulating real-time network traffic monitoring..."
    
    5.times do |i|
      event = generate_network_event(i)
      @demo_log << event
      
      # Check security status
      if @blocked_ips.include?(event[:source_ip])
        puts "   🚨 BLOCKED: #{event[:source_ip]} -> #{event[:destination_ip]} (malicious IP)"
      elsif @trusted_ips.include?(event[:source_ip])
        puts "   ✓ ALLOWED: #{event[:source_ip]} -> #{event[:destination_ip]} (trusted IP)"
      else
        puts "   ⚠ MONITORED: #{event[:source_ip]} -> #{event[:destination_ip]} (unknown IP)"
      end
      
      sleep 0.8
    end
    
    puts "   ✓ Network monitoring simulation complete"
    puts
  end

  def demo_security_incident
    puts "5. Security Incident Response"
    puts "   Demonstrating automated security response..."
    
    # Simulate suspicious activity
    suspicious_ip = "203.0.113.200"
    puts "   🚨 ALERT: Suspicious activity detected from #{suspicious_ip}"
    log_event("SECURITY_ALERT", "Suspicious activity from #{suspicious_ip}")
    sleep 1
    
    # Automatic response
    puts "   🔒 RESPONSE: Automatically blocking #{suspicious_ip}"
    block_ip(suspicious_ip)
    log_event("AUTO_BLOCK", "Automatically blocked #{suspicious_ip}")
    sleep 1
    
    # Attempted access from blocked IP
    puts "   ✗ BLOCKED: Access attempt from #{suspicious_ip} was prevented"
    log_event("ACCESS_DENIED", "Blocked access attempt from #{suspicious_ip}")
    
    puts "   ✓ Security incident handled automatically"
    puts
  end

  def demo_log_analysis
    puts "6. Security Log Analysis"
    puts "   Analyzing security events and logs..."
    
    if File.exist?("zerotrust_log.json")
      puts "   Recent security events:"
      
      File.open("zerotrust_log.json", "r") do |file|
        lines = file.readlines
        recent_events = lines.last(5)
        
        recent_events.each do |line|
          begin
            log_entry = JSON.parse(line.strip)
            timestamp = log_entry['timestamp'] || 'Unknown'
            event_type = log_entry['event_type'] || 'UNKNOWN'
            description = log_entry['description'] || 'No description'
            
            # Color coding
            case event_type
            when 'SECURITY_ALERT', 'AUTO_BLOCK', 'ACCESS_DENIED'
              color = "\033[31m"  # Red
            when 'TRUST_IP'
              color = "\033[32m"  # Green
            when 'BLOCK_IP'
              color = "\033[35m"  # Magenta
            else
              color = "\033[37m"  # White
            end
            reset = "\033[0m"
            
            puts "   #{color}[#{timestamp}] #{event_type}: #{description}#{reset}"
          rescue JSON::ParserError => e
            puts "   Error parsing log entry"
          end
        end
      end
    else
      puts "   No logs found"
    end
    
    puts "   ✓ Log analysis complete"
    puts
  end

  def generate_network_event(index)
    source_ips = @trusted_ips + @blocked_ips + ["192.168.1.#{100 + index}", "10.0.0.#{50 + index}"]
    dest_ips = ["192.168.1.1", "10.0.0.1", "8.8.8.8"]
    protocols = ["TCP/80", "TCP/443", "TCP/22"]
    
    {
      timestamp: Time.now.strftime("%Y-%m-%d %H:%M:%S"),
      source_ip: source_ips.sample,
      destination_ip: dest_ips.sample,
      protocol: protocols.sample
    }
  end

  def add_trusted_ip(ip)
    unless @trusted_ips.include?(ip)
      @trusted_ips << ip
      @blocked_ips.delete(ip) if @blocked_ips.include?(ip)
      
      # Call the actual ZeroTrustScope function
      ZeroTrustScope.add_trusted_ip(ip)
      
      log_event("TRUST_IP", "Added trusted IP: #{ip}")
    end
  end

  def block_ip(ip)
    unless @blocked_ips.include?(ip)
      @blocked_ips << ip
      @trusted_ips.delete(ip) if @trusted_ips.include?(ip)
      
      # Call the actual ZeroTrustScope function
      ZeroTrustScope.block_untrusted_ip(ip)
      
      log_event("BLOCK_IP", "Blocked IP: #{ip}")
    end
  end

  def log_event(event_type, description)
    log_entry = {
      timestamp: Time.now.strftime("%Y-%m-%d %H:%M:%S"),
      event_type: event_type,
      description: description,
      source: "demo"
    }
    
    FileUtils.touch("zerotrust_log.json") unless File.exist?("zerotrust_log.json")
    File.open("zerotrust_log.json", "a") do |f|
      f.puts(log_entry.to_json)
    end
  end

  def load_config
    begin
      JSON.parse(File.read("config.json"))
    rescue => e
      nil
    end
  end
end

if __FILE__ == $0
  demo = ZeroTrustDemo.new
  demo.run_demo
end 
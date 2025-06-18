#!/usr/bin/env ruby

require 'json'
require 'fileutils'
require 'time'
require 'securerandom'

# Load the ZeroTrustScope module
begin
  require_relative 'zerotrust_scope'
  FFI_AVAILABLE = true
rescue LoadError => e
  puts "Warning: Could not load zerotrust_scope module: #{e.message}"
  puts "Using Ruby stub implementation for simulation..."
  FFI_AVAILABLE = false
  require_relative 'zerotrust_stub'
end

class ZeroTrustSimulator
  def initialize
    @config = load_config
    @simulation_log = []
    @trusted_ips = []
    @blocked_ips = []
    @network_events = []
    @simulation_running = false
  end

  def run_simulation
    puts "=== ZeroTrustScope Network Simulation ==="
    puts "This simulation demonstrates ZeroTrust security in action"
    puts "Press Ctrl+C to stop the simulation"
    puts

    # Initialize the system
    setup_simulation
    display_menu
  end

  private

  def setup_simulation
    # Create initial trusted IPs
    @trusted_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.10"]
    
    # Create initial blocked IPs
    @blocked_ips = ["203.0.113.45", "198.51.100.123"]
    
    # Generate some initial network events
    generate_network_events
    
    puts "✓ Simulation environment initialized"
    puts "  - Trusted IPs: #{@trusted_ips.join(', ')}"
    puts "  - Blocked IPs: #{@blocked_ips.join(', ')}"
    puts "  - Network events generated: #{@network_events.length}"
    puts
  end

  def display_menu
    loop do
      puts "=== Simulation Menu ==="
      puts "1. Start real-time monitoring"
      puts "2. Add trusted IP"
      puts "3. Block IP address"
      puts "4. View current status"
      puts "5. Generate network traffic"
      puts "6. View security logs"
      puts "7. Run automated scenario"
      puts "8. Exit"
      puts
      print "Select option (1-8): "
      
      choice = gets.chomp.strip
      puts
      
      case choice
      when "1"
        start_monitoring
      when "2"
        add_trusted_ip_interactive
      when "3"
        block_ip_interactive
      when "4"
        show_status
      when "5"
        generate_traffic
      when "6"
        show_logs
      when "7"
        run_automated_scenario
      when "8"
        puts "Simulation ended."
        break
      else
        puts "Invalid option. Please try again."
      end
      puts
    end
  end

  def start_monitoring
    puts "Starting real-time network monitoring..."
    puts "Press Ctrl+C to stop monitoring"
    puts
    
    @simulation_running = true
    
    begin
      loop do
        # Simulate network activity
        simulate_network_activity
        
        # Check for security events
        check_security_events
        
        # Display real-time status
        display_real_time_status
        
        sleep 2
      end
    rescue Interrupt
      puts "\nMonitoring stopped."
      @simulation_running = false
    end
  end

  def add_trusted_ip_interactive
    print "Enter IP address to trust: "
    ip = gets.chomp.strip
    
    if valid_ip?(ip)
      add_trusted_ip(ip)
    else
      puts "Invalid IP address format. Please use xxx.xxx.xxx.xxx"
    end
  end

  def block_ip_interactive
    print "Enter IP address to block: "
    ip = gets.chomp.strip
    
    if valid_ip?(ip)
      block_ip(ip)
    else
      puts "Invalid IP address format. Please use xxx.xxx.xxx.xxx"
    end
  end

  def show_status
    puts "=== Current System Status ==="
    puts "Trusted IPs (#{@trusted_ips.length}):"
    @trusted_ips.each { |ip| puts "  ✓ #{ip}" }
    puts
    puts "Blocked IPs (#{@blocked_ips.length}):"
    @blocked_ips.each { |ip| puts "  ✗ #{ip}" }
    puts
    puts "Recent Network Events (#{@network_events.length}):"
    @network_events.last(5).each do |event|
      status = @trusted_ips.include?(event[:source_ip]) ? "✓" : "?"
      puts "  #{status} #{event[:timestamp]} - #{event[:source_ip]} -> #{event[:destination_ip]} (#{event[:protocol]})"
    end
  end

  def generate_traffic
    puts "Generating simulated network traffic..."
    
    5.times do
      event = generate_random_network_event
      @network_events << event
      
      # Log the event
      log_event("NETWORK_TRAFFIC", "Traffic from #{event[:source_ip]} to #{event[:destination_ip]} (#{event[:protocol]})")
      
      # Check if this should trigger security action
      if @blocked_ips.include?(event[:source_ip])
        log_event("SECURITY_ALERT", "Blocked traffic from blocked IP: #{event[:source_ip]}")
        puts "🚨 ALERT: Blocked traffic from #{event[:source_ip]}"
      elsif !@trusted_ips.include?(event[:source_ip]) && rand < 0.3
        log_event("SECURITY_WARNING", "Untrusted IP detected: #{event[:source_ip]}")
        puts "⚠️  WARNING: Untrusted IP #{event[:source_ip]} detected"
      end
      
      sleep 0.5
    end
    
    puts "Traffic generation complete."
  end

  def show_logs
    puts "=== Security Logs ==="
    
    if File.exist?("zerotrust_log.json")
      File.open("zerotrust_log.json", "r") do |file|
        file.each_line do |line|
          begin
            log_entry = JSON.parse(line.strip)
            timestamp = log_entry['timestamp'] || 'Unknown'
            event_type = log_entry['event_type'] || 'UNKNOWN'
            description = log_entry['description'] || 'No description'
            
            # Color coding
            case event_type
            when 'SECURITY_ALERT'
              color = "\033[31m"  # Red
            when 'SECURITY_WARNING'
              color = "\033[33m"  # Yellow
            when 'TRUST_IP'
              color = "\033[32m"  # Green
            when 'BLOCK_IP'
              color = "\033[35m"  # Magenta
            else
              color = "\033[37m"  # White
            end
            reset = "\033[0m"
            
            puts "#{color}[#{timestamp}] [#{event_type}] #{description}#{reset}"
          rescue JSON::ParserError => e
            puts "Error parsing log entry: #{e.message}"
          end
        end
      end
    else
      puts "No logs found."
    end
  end

  def run_automated_scenario
    puts "=== Running Automated Security Scenario ==="
    puts "This scenario demonstrates a typical security incident response"
    puts
    
    # Scenario 1: Suspicious activity detection
    puts "1. Detecting suspicious network activity..."
    suspicious_ip = "203.0.113.100"
    log_event("SECURITY_ALERT", "Suspicious activity detected from #{suspicious_ip}")
    puts "   🚨 Suspicious activity from #{suspicious_ip}"
    sleep 2
    
    # Scenario 2: Automatic blocking
    puts "2. Automatically blocking suspicious IP..."
    block_ip(suspicious_ip)
    sleep 2
    
    # Scenario 3: Attempted access from blocked IP
    puts "3. Attempted access from blocked IP..."
    event = {
      timestamp: Time.now.strftime("%Y-%m-%d %H:%M:%S"),
      source_ip: suspicious_ip,
      destination_ip: "192.168.1.1",
      protocol: "TCP/80",
      action: "BLOCKED"
    }
    @network_events << event
    log_event("SECURITY_ALERT", "Blocked access attempt from #{suspicious_ip}")
    puts "   ✗ Access attempt from #{suspicious_ip} was blocked"
    sleep 2
    
    # Scenario 4: Adding trusted IP
    puts "4. Adding new trusted IP..."
    new_trusted_ip = "192.168.1.200"
    add_trusted_ip(new_trusted_ip)
    sleep 2
    
    # Scenario 5: Successful trusted access
    puts "5. Trusted IP accessing network..."
    event = {
      timestamp: Time.now.strftime("%Y-%m-%d %H:%M:%S"),
      source_ip: new_trusted_ip,
      destination_ip: "192.168.1.1",
      protocol: "TCP/443",
      action: "ALLOWED"
    }
    @network_events << event
    log_event("NETWORK_TRAFFIC", "Trusted access from #{new_trusted_ip}")
    puts "   ✓ Trusted access from #{new_trusted_ip} allowed"
    
    puts
    puts "Scenario completed successfully!"
  end

  def simulate_network_activity
    # Generate random network events
    if rand < 0.7  # 70% chance of new event
      event = generate_random_network_event
      @network_events << event
      
      # Keep only last 50 events
      @network_events = @network_events.last(50)
    end
  end

  def check_security_events
    return if @network_events.empty?
    
    latest_event = @network_events.last
    
    # Check if source IP is blocked
    if @blocked_ips.include?(latest_event[:source_ip])
      log_event("SECURITY_ALERT", "Blocked traffic from blocked IP: #{latest_event[:source_ip]}")
      puts "🚨 BLOCKED: #{latest_event[:source_ip]} -> #{latest_event[:destination_ip]}"
    end
    
    # Check for suspicious patterns (simplified)
    if !@trusted_ips.include?(latest_event[:source_ip]) && rand < 0.2
      log_event("SECURITY_WARNING", "Untrusted IP detected: #{latest_event[:source_ip]}")
      puts "⚠️  WARNING: Untrusted IP #{latest_event[:source_ip]} detected"
    end
  end

  def display_real_time_status
    return unless @simulation_running
    
    # Clear screen (Windows)
    system('cls') rescue system('clear')
    
    puts "=== ZeroTrustScope Real-Time Monitoring ==="
    puts "Time: #{Time.now.strftime("%Y-%m-%d %H:%M:%S")}"
    puts "Status: ACTIVE"
    puts
    
    puts "Trusted IPs: #{@trusted_ips.length} | Blocked IPs: #{@blocked_ips.length}"
    puts "Network Events: #{@network_events.length}"
    puts
    
    if @network_events.any?
      puts "Recent Activity:"
      @network_events.last(3).each do |event|
        status = @trusted_ips.include?(event[:source_ip]) ? "✓" : 
                @blocked_ips.include?(event[:source_ip]) ? "✗" : "?"
        puts "  #{status} #{event[:timestamp]} - #{event[:source_ip]} -> #{event[:destination_ip]}"
      end
    end
    
    puts
    puts "Press Ctrl+C to stop monitoring"
  end

  def generate_random_network_event
    source_ips = @trusted_ips + @blocked_ips + ["192.168.1.#{rand(1..254)}", "10.0.0.#{rand(1..254)}"]
    dest_ips = ["192.168.1.1", "10.0.0.1", "8.8.8.8", "1.1.1.1"]
    protocols = ["TCP/80", "TCP/443", "TCP/22", "UDP/53", "ICMP"]
    
    {
      timestamp: Time.now.strftime("%Y-%m-%d %H:%M:%S"),
      source_ip: source_ips.sample,
      destination_ip: dest_ips.sample,
      protocol: protocols.sample,
      action: "DETECTED"
    }
  end

  def generate_network_events
    10.times do
      @network_events << generate_random_network_event
    end
  end

  def add_trusted_ip(ip)
    unless @trusted_ips.include?(ip)
      @trusted_ips << ip
      @blocked_ips.delete(ip) if @blocked_ips.include?(ip)
      
      # Call the actual ZeroTrustScope function
      ZeroTrustScope.add_trusted_ip(ip)
      
      log_event("TRUST_IP", "Added trusted IP: #{ip}")
      puts "✓ Successfully added #{ip} to trusted IPs"
    else
      puts "IP #{ip} is already trusted"
    end
  end

  def block_ip(ip)
    unless @blocked_ips.include?(ip)
      @blocked_ips << ip
      @trusted_ips.delete(ip) if @trusted_ips.include?(ip)
      
      # Call the actual ZeroTrustScope function
      ZeroTrustScope.block_untrusted_ip(ip)
      
      log_event("BLOCK_IP", "Blocked IP: #{ip}")
      puts "✓ Successfully blocked #{ip}"
    else
      puts "IP #{ip} is already blocked"
    end
  end

  def valid_ip?(ip)
    return false unless ip.match(/\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/)
    octets = ip.split('.')
    octets.all? { |octet| octet.to_i >= 0 && octet.to_i <= 255 }
  end

  def log_event(event_type, description)
    log_entry = {
      timestamp: Time.now.strftime("%Y-%m-%d %H:%M:%S"),
      event_type: event_type,
      description: description,
      source: "simulation"
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
      puts "Warning: Could not load config.json: #{e.message}"
      nil
    end
  end
end

if __FILE__ == $0
  simulator = ZeroTrustSimulator.new
  simulator.run_simulation
end 
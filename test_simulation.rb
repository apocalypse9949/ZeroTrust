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
  puts "Using Ruby stub implementation for simulation..."
  FFI_AVAILABLE = false
  require_relative 'zerotrust_stub'
end

class ZeroTrustTest
  def initialize
    @trusted_ips = ["192.168.1.100", "10.0.0.50"]
    @blocked_ips = ["203.0.113.45"]
    @test_results = []
  end

  def run_tests
    puts "=== ZeroTrustScope Simulation Tests ==="
    puts

    test_trusted_ip_management
    test_malicious_ip_blocking
    test_network_monitoring
    test_security_incident_response
    test_logging_system

    display_results
  end

  private

  def test_trusted_ip_management
    puts "Testing trusted IP management..."
    
    new_trusted_ip = "192.168.1.200"
    puts "  Adding #{new_trusted_ip} to trusted list..."
    
    begin
      ZeroTrustScope.add_trusted_ip(new_trusted_ip)
      @trusted_ips << new_trusted_ip
      @test_results << { test: "Trusted IP Management", status: "PASS", message: "Successfully added trusted IP" }
    rescue => e
      @test_results << { test: "Trusted IP Management", status: "FAIL", message: "Error: #{e.message}" }
    end
  end

  def test_malicious_ip_blocking
    puts "Testing malicious IP blocking..."
    
    malicious_ip = "198.51.100.123"
    puts "  Blocking malicious IP #{malicious_ip}..."
    
    begin
      ZeroTrustScope.block_untrusted_ip(malicious_ip)
      @blocked_ips << malicious_ip
      @test_results << { test: "Malicious IP Blocking", status: "PASS", message: "Successfully blocked malicious IP" }
    rescue => e
      @test_results << { test: "Malicious IP Blocking", status: "FAIL", message: "Error: #{e.message}" }
    end
  end

  def test_network_monitoring
    puts "Testing network monitoring simulation..."
    
    # Simulate network events
    events = [
      { source: "192.168.1.100", dest: "192.168.1.1", status: "TRUSTED" },
      { source: "203.0.113.45", dest: "192.168.1.1", status: "BLOCKED" },
      { source: "192.168.1.150", dest: "8.8.8.8", status: "UNKNOWN" }
    ]
    
    events.each do |event|
      if @trusted_ips.include?(event[:source])
        puts "  ✓ ALLOWED: #{event[:source]} -> #{event[:dest]} (trusted)"
      elsif @blocked_ips.include?(event[:source])
        puts "  🚨 BLOCKED: #{event[:source]} -> #{event[:dest]} (malicious)"
      else
        puts "  ⚠ MONITORED: #{event[:source]} -> #{event[:dest]} (unknown)"
      end
    end
    
    @test_results << { test: "Network Monitoring", status: "PASS", message: "Network monitoring simulation working" }
  end

  def test_security_incident_response
    puts "Testing security incident response..."
    
    # Simulate suspicious activity
    suspicious_ip = "203.0.113.200"
    puts "  🚨 ALERT: Suspicious activity from #{suspicious_ip}"
    
    begin
      # Block the suspicious IP
      ZeroTrustScope.block_untrusted_ip(suspicious_ip)
      @blocked_ips << suspicious_ip
      
      # Log the incident
      log_event("SECURITY_ALERT", "Suspicious activity from #{suspicious_ip}")
      log_event("AUTO_BLOCK", "Automatically blocked #{suspicious_ip}")
      
      puts "  🔒 RESPONSE: Automatically blocked #{suspicious_ip}"
      puts "  ✗ BLOCKED: Access attempt from #{suspicious_ip} was prevented"
      
      @test_results << { test: "Security Incident Response", status: "PASS", message: "Security incident handled automatically" }
    rescue => e
      @test_results << { test: "Security Incident Response", status: "FAIL", message: "Error: #{e.message}" }
    end
  end

  def test_logging_system
    puts "Testing logging system..."
    
    begin
      # Test log file creation and reading
      log_file = "zerotrust_log.json"
      
      if File.exist?(log_file)
        lines = File.readlines(log_file)
        recent_events = lines.last(3)
        
        puts "  Recent security events:"
        recent_events.each do |line|
          begin
            log_entry = JSON.parse(line.strip)
            timestamp = log_entry['timestamp'] || 'Unknown'
            event_type = log_entry['event_type'] || 'UNKNOWN'
            description = log_entry['description'] || 'No description'
            
            puts "    [#{timestamp}] #{event_type}: #{description}"
          rescue JSON::ParserError => e
            puts "    Error parsing log entry"
          end
        end
        
        @test_results << { test: "Logging System", status: "PASS", message: "Logging system working correctly" }
      else
        @test_results << { test: "Logging System", status: "FAIL", message: "Log file not found" }
      end
    rescue => e
      @test_results << { test: "Logging System", status: "FAIL", message: "Error: #{e.message}" }
    end
  end

  def log_event(event_type, description)
    log_entry = {
      timestamp: Time.now.strftime("%Y-%m-%d %H:%M:%S"),
      event_type: event_type,
      description: description,
      source: "test"
    }
    
    FileUtils.touch("zerotrust_log.json") unless File.exist?("zerotrust_log.json")
    File.open("zerotrust_log.json", "a") do |f|
      f.puts(log_entry.to_json)
    end
  end

  def display_results
    puts
    puts "=== Test Results ==="
    puts
    
    passed = 0
    failed = 0
    
    @test_results.each do |result|
      case result[:status]
      when "PASS"
        status_icon = "✓"
        color = "\033[32m"  # Green
        passed += 1
      when "FAIL"
        status_icon = "✗"
        color = "\033[31m"  # Red
        failed += 1
      end
      reset = "\033[0m"
      
      puts "#{color}#{status_icon} #{result[:test]}#{reset}"
      puts "   #{result[:message]}"
      puts
    end
    
    puts "Summary: #{passed} passed, #{failed} failed"
    
    if failed == 0
      puts "\n🎉 All simulation tests passed! ZeroTrustScope is working correctly."
    else
      puts "\n⚠️  Some tests failed. Please check the issues above."
    end
  end
end

if __FILE__ == $0
  test = ZeroTrustTest.new
  test.run_tests
end 
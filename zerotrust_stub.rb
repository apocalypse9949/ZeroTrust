# ZeroTrustScope Ruby Stub
# This module provides stub implementations of C functions for testing
# when the actual C library isn't compiled

require 'json'
require 'fileutils'

module ZeroTrustScope
  class StubImplementation
    def self.start_monitoring
      puts "[*] Stub: Starting packet monitoring (C library not compiled)"
      log_event("MONITOR_START", "Packet monitoring started (stub mode)")
    end

    def self.add_trusted_ip(ip_address)
      puts "[*] Stub: Adding trusted IP #{ip_address} (C library not compiled)"
      log_event("TRUST_IP", "Added trusted IP: #{ip_address}")
    end

    def self.block_untrusted_ip(ip_address)
      puts "[*] Stub: Blocking untrusted IP #{ip_address} (C library not compiled)"
      log_event("BLOCK_IP", "Blocked untrusted IP: #{ip_address}")
    end

    private

    def self.log_event(event_type, description)
      log_entry = {
        timestamp: Time.now.strftime("%Y-%m-%d %H:%M:%S"),
        event_type: event_type,
        description: description,
        source: "stub"
      }
      
      FileUtils.touch("zerotrust_log.json") unless File.exist?("zerotrust_log.json")
      File.open("zerotrust_log.json", "a") do |f|
        f.puts(log_entry.to_json)
      end
    end
  end

  # Create module methods that delegate to the stub
  def self.start_monitoring
    StubImplementation.start_monitoring
  end

  def self.add_trusted_ip(ip_address)
    StubImplementation.add_trusted_ip(ip_address)
  end

  def self.block_untrusted_ip(ip_address)
    StubImplementation.block_untrusted_ip(ip_address)
  end

  # CLI class for command-line interface
  class CLI
    def self.start(args)
      case args.first
      when "start"
        puts "Starting ZeroTrustScope network monitoring (stub mode)..."
        ZeroTrustScope.start_monitoring()
      when "trust"
        if args[1]
          puts "Adding #{args[1]} to trusted IPs (stub mode)..."
          ZeroTrustScope.add_trusted_ip(args[1])
        else
          puts "Usage: ruby zerotrust_stub.rb trust <IP_ADDRESS>"
        end
      when "block"
        if args[1]
          puts "Blocking #{args[1]} (stub mode)..."
          ZeroTrustScope.block_untrusted_ip(args[1])
        else
          puts "Usage: ruby zerotrust_stub.rb block <IP_ADDRESS>"
        end
      when "logs"
        puts "Displaying real-time logs (stub mode) - Ctrl+C to stop:"
        loop do
          if File.exist?("zerotrust_log.json")
            File.open("zerotrust_log.json", "r") do |file|
              file.each_line do |line|
                begin
                  log_entry = JSON.parse(line)
                  puts "[#{log_entry['timestamp']}] [#{log_entry['event_type']}] #{log_entry['description']}"
                rescue JSON::ParserError => e
                  puts "Error parsing log entry: #{e.message}"
                end
              end
            end
            File.truncate("zerotrust_log.json", 0)
          end
          sleep 1
        end
      else
        puts "ZeroTrustScope Stub Mode"
        puts "Usage:"
        puts "  ruby zerotrust_stub.rb start     - Start monitoring"
        puts "  ruby zerotrust_stub.rb trust IP  - Add trusted IP"
        puts "  ruby zerotrust_stub.rb block IP  - Block IP"
        puts "  ruby zerotrust_stub.rb logs      - Show logs"
        puts ""
        puts "Note: This is stub mode - C library not compiled"
      end
    end
  end
end

# Allow direct execution
if __FILE__ == $0
  ZeroTrustScope::CLI.start(ARGV)
end 
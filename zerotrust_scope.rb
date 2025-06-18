require 'ffi'
require 'json'
require 'thor'

module ZeroTrustScope
  extend FFI::Library

  # Use absolute path to the DLL
  current_dir = File.dirname(File.expand_path(__FILE__))
  ffi_lib File.join(current_dir, "zerotrust.dll")

  # C function declarations
  attach_function :c_start_monitoring, :start_monitoring, [], :void
  attach_function :c_add_trusted_ip, :add_trusted_ip, [:string], :void
  attach_function :c_block_untrusted_ip, :block_untrusted_ip, [:string], :void

  # Module-level methods for external use
  def self.start_monitoring
    puts "Starting ZeroTrustScope network monitoring..."
    c_start_monitoring()
  end

  def self.add_trusted_ip(ip_address)
    puts "Adding #{ip_address} to trusted IPs..."
    c_add_trusted_ip(ip_address)
  end

  def self.block_untrusted_ip(ip_address)
    puts "Blocking #{ip_address}..."
    c_block_untrusted_ip(ip_address)
  end

  class CLI < Thor
    desc "start", "Start network monitoring"
    def start
      ZeroTrustScope.start_monitoring
    end

    desc "trust IP_ADDRESS", "Add an IP address to the trusted list"
    def trust(ip_address)
      ZeroTrustScope.add_trusted_ip(ip_address)
    end

    desc "block IP_ADDRESS", "Block an IP address"
    def block(ip_address)
      ZeroTrustScope.block_untrusted_ip(ip_address)
    end

    desc "logs", "Display real-time security logs"
    def logs
      puts "Displaying real-time logs (Ctrl+C to stop):"
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
          # Clear the file after reading to avoid re-processing old entries
          File.truncate("zerotrust_log.json", 0)
        end
        sleep 1 # Check for new logs every second
      end
    end
  end
end

# Only start CLI if this file is run directly
if __FILE__ == $0
  ZeroTrustScope::CLI.start(ARGV)
end 
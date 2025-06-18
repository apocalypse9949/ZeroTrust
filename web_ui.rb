require 'sinatra'
require 'sinatra/reloader'
require 'json'
require_relative 'zerotrust_scope'

class ZeroTrustWebUI < Sinatra::Base
  configure :development do
    register Sinatra::Reloader
  end

  set :port, 4567
  set :bind, '0.0.0.0'

  get '/' do
    erb :dashboard
  end

  get '/api/status' do
    content_type :json
    {
      status: 'running',
      timestamp: Time.now.iso8601,
      logs: get_recent_logs
    }.to_json
  end

  post '/api/trust' do
    content_type :json
    ip = params[:ip]
    
    if ip && ip.match(/\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/)
      ZeroTrustScope.add_trusted_ip(ip)
      { success: true, message: "Added #{ip} to trusted IPs" }.to_json
    else
      { success: false, message: "Invalid IP address format" }.to_json
    end
  end

  post '/api/block' do
    content_type :json
    ip = params[:ip]
    
    if ip && ip.match(/\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/)
      ZeroTrustScope.block_untrusted_ip(ip)
      { success: true, message: "Blocked #{ip}" }.to_json
    else
      { success: false, message: "Invalid IP address format" }.to_json
    end
  end

  get '/api/logs' do
    content_type :json
    { logs: get_recent_logs }.to_json
  end

  private

  def get_recent_logs
    logs = []
    if File.exist?("zerotrust_log.json")
      File.open("zerotrust_log.json", "r") do |file|
        file.each_line do |line|
          begin
            logs << JSON.parse(line)
          rescue JSON::ParserError
            # Skip malformed log entries
          end
        end
      end
    end
    logs.last(50) # Return last 50 log entries
  end
end

# HTML template for dashboard
__END__

@@ dashboard
<!DOCTYPE html>
<html>
<head>
    <title>ZeroTrustScope Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .card { background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .form-group { margin: 10px 0; }
        input[type="text"] { padding: 8px; width: 200px; border: 1px solid #ddd; border-radius: 3px; }
        button { padding: 8px 16px; background: #3498db; color: white; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background: #2980b9; }
        .alert { background: #e74c3c; color: white; padding: 10px; margin: 10px 0; border-radius: 3px; }
        .info { background: #3498db; color: white; padding: 10px; margin: 10px 0; border-radius: 3px; }
        .log-entry { padding: 5px; border-bottom: 1px solid #eee; }
        .log-timestamp { color: #666; font-size: 0.9em; }
        .log-alert { color: #e74c3c; font-weight: bold; }
        .log-info { color: #3498db; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ZeroTrustScope Dashboard</h1>
            <p>Real-time network security monitoring and control</p>
        </div>

        <div class="card">
            <h2>IP Management</h2>
            <div class="form-group">
                <label>IP Address:</label>
                <input type="text" id="ipInput" placeholder="192.168.1.100">
                <button onclick="trustIP()">Trust IP</button>
                <button onclick="blockIP()">Block IP</button>
            </div>
        </div>

        <div class="card">
            <h2>Security Logs</h2>
            <button onclick="refreshLogs()">Refresh Logs</button>
            <div id="logs"></div>
        </div>
    </div>

    <script>
        function trustIP() {
            const ip = document.getElementById('ipInput').value;
            fetch('/api/trust', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `ip=${ip}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Success: ' + data.message);
                } else {
                    alert('Error: ' + data.message);
                }
            });
        }

        function blockIP() {
            const ip = document.getElementById('ipInput').value;
            fetch('/api/block', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `ip=${ip}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Success: ' + data.message);
                } else {
                    alert('Error: ' + data.message);
                }
            });
        }

        function refreshLogs() {
            fetch('/api/logs')
            .then(response => response.json())
            .then(data => {
                const logsDiv = document.getElementById('logs');
                logsDiv.innerHTML = '';
                data.logs.reverse().forEach(log => {
                    const logEntry = document.createElement('div');
                    logEntry.className = 'log-entry';
                    const alertClass = log.event_type === 'ALERT' ? 'log-alert' : 'log-info';
                    logEntry.innerHTML = `
                        <span class="log-timestamp">[${log.timestamp}]</span>
                        <span class="${alertClass}">[${log.event_type}]</span>
                        ${log.description}
                    `;
                    logsDiv.appendChild(logEntry);
                });
            });
        }

        // Auto-refresh logs every 5 seconds
        setInterval(refreshLogs, 5000);
        refreshLogs(); // Initial load
    </script>
</body>
</html> 
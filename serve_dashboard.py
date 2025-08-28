#!/usr/bin/env python3
"""
Simple HTTP server for Kong Guard AI Dashboard
Serves the enterprise demo dashboard on port 8080
"""

import http.server
import socketserver
import os
import sys

PORT = 8080
DASHBOARD_FILE = "enterprise_demo_dashboard.html"

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/dashboard":
            # Redirect to the main dashboard
            self.send_response(302)
            self.send_header("Location", f"/{DASHBOARD_FILE}")
            self.end_headers()
        else:
            super().do_GET()

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    Handler = DashboardHandler
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"🎯 Kong Guard AI Dashboard Server")
        print(f"=" * 50)
        print(f"✅ Dashboard running at: http://localhost:{PORT}")
        print(f"📊 Main dashboard: http://localhost:{PORT}/{DASHBOARD_FILE}")
        print(f"📁 Available dashboards:")
        print(f"   - http://localhost:{PORT}/enterprise_demo_dashboard.html")
        print(f"   - http://localhost:{PORT}/kong-dashboard.html")  
        print(f"   - http://localhost:{PORT}/visualization/simple-ai-dashboard.html")
        print(f"   - http://localhost:{PORT}/attack_reports.html")
        print(f"=" * 50)
        print(f"Press Ctrl+C to stop the server")
        
        httpd.serve_forever()
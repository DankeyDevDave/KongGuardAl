#!/usr/bin/env python3
"""
Simple HTTP server for Kong Guard AI Dashboard
Serves the enterprise demo dashboard on port 8080
"""

import http.server
import os
import socketserver

PORT = 12345
DASHBOARD_FILE = "enterprise_demo_dashboard.html"


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/dashboard":
            # Redirect to the unified dashboard
            self.send_response(302)
            self.send_header("Location", "/unified_dashboard.html")
            self.end_headers()
        else:
            super().do_GET()


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    Handler = DashboardHandler

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("🎯 Kong Guard AI Dashboard Server")
        print("=" * 50)
        print(f"✅ Dashboard running at: http://localhost:{PORT}")
        print(f"📊 Main dashboard: http://localhost:{PORT}/{DASHBOARD_FILE}")
        print(f"🔄 Unified dashboard: http://localhost:{PORT}/unified_dashboard.html")
        print("📁 Available dashboards:")
        print(f"   - http://localhost:{PORT}/enterprise_demo_dashboard.html")
        print(f"   - http://localhost:{PORT}/enterprise_attack_dashboard.html")
        print(f"   - http://localhost:{PORT}/kong-dashboard.html")
        print(f"   - http://localhost:{PORT}/attack_reports.html")
        print(f"   - http://localhost:{PORT}/protection-module-test.html")
        print(f"   - http://localhost:{PORT}/visualization/simple-ai-dashboard.html")
        print(f"   - http://localhost:{PORT}/visualization/ai-insights.html")
        print("=" * 50)
        print("Press Ctrl+C to stop the server")

        httpd.serve_forever()

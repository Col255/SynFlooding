#!/bin/bash
set -e

echo "=================================================="
echo " [!] VICTIM SERVER INITIALIZING..."
echo " [*] IP Address: 192.168.100.10"
echo " [*] Service: Nginx HTTP Server (Port 80)"
echo "=================================================="

# Ensure Nginx log directory exists
mkdir -p /var/log/nginx

# Launch Nginx in foreground to keep container running and accept traffic
exec nginx -g "daemon off;"

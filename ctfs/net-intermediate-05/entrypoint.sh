#!/bin/sh
# Start the SSH daemon in the background, then run the web app in the foreground
# (keeps the container alive and gives us PID 1 = the thing we care about).
set -e
mkdir -p /run/sshd
/usr/sbin/sshd
exec python3 /opt/app/app.py

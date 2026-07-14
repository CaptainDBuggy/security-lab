#!/bin/sh
# Start sshd + cron in the background, then run the web app in the foreground
# (keeps the container alive; PID 1 = the web app we care about).
set -e
mkdir -p /run/sshd
/usr/sbin/sshd
# cron is what makes the priv-esc live: it ticks the root healthcheck job.
cron
exec python3 /opt/app/app.py

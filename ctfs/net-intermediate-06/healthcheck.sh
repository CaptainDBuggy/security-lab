#!/bin/sh
# Relay node health probe. Runs every minute via cron AS ROOT.
# (Ops left this world-writable so "anyone on the box could tweak the checks."
#  That is the whole bug: a root-run script a low-priv user can edit.)
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') relay healthy" >> /var/log/relay-health.log 2>&1

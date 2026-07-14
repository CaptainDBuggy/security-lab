#!/bin/sh
# sshd as root; web app dropped to www-data (LFI lands you as www-data, and
# crucially cannot read /etc/shadow — you must crack the leaked backup hash).
set -e
mkdir -p /run/sshd
/usr/sbin/sshd
exec su -s /bin/bash -c "python3 /var/www/keyring/app.py" www-data

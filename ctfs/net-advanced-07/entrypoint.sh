#!/bin/sh
# sshd runs as root (it needs to). The WEB APP is dropped to the low-priv
# www-data user on purpose: RCE via the app lands you as www-data, NOT root,
# so the box still has to be escalated. www-data's login shell is nologin, so
# we launch with an explicit shell via su -s.
set -e
mkdir -p /run/sshd
/usr/sbin/sshd
exec su -s /bin/bash -c "python3 /var/www/forge/app.py" www-data

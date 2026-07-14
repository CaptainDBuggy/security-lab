# Forge — advanced network/Linux boot2root CTF (CTF 07).
# A 3-HOP chain, unlike the single-jump boxes before it:
#   1) web OS-command-injection  -> RCE as www-data (foothold is EARNED, not a
#      leaked SSH password)
#   2) lateral movement          -> deploy creds sitting in a web-readable config
#   3) SUID + PATH-hijack         -> root (a NEW priv-esc pattern: a SUID-root
#      binary that calls `tar` by name)
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo gcc libc6-dev iputils-ping tar \
        findutils procps iproute2 ca-certificates less \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir flask==3.0.3

# --- users ---------------------------------------------------------------
# www-data already exists (runs the web app). Create the 'deploy' service user
# (the lateral-movement target) with the password the web config leaks.
RUN useradd -m -s /bin/bash deploy \
    && echo 'deploy:F0rge-D3pl0y-2026!' | chpasswd

# --- web app (runs as www-data) ------------------------------------------
RUN mkdir -p /var/www/forge
COPY app.py    /var/www/forge/app.py
COPY config.py /var/www/forge/config.py
# config.py holds deploy's password; www-data must be able to read it (it's the
# app's config) — which is exactly the lateral-movement bug.
RUN chown -R www-data:www-data /var/www/forge \
    && chmod 750 /var/www/forge \
    && chmod 640 /var/www/forge/config.py

# --- SUID priv-esc binary ------------------------------------------------
# Compiled SUID-root, but group-restricted to 'deploy' (mode 4750) so www-data
# CANNOT run it — you must land the lateral move to deploy first, then abuse it.
COPY forge-backup.c /tmp/forge-backup.c
RUN gcc -O2 -o /usr/local/bin/forge-backup /tmp/forge-backup.c \
    && rm -f /tmp/forge-backup.c \
    && chown root:deploy /usr/local/bin/forge-backup \
    && chmod 4750 /usr/local/bin/forge-backup \
    && mkdir -p /var/backups

# --- flags ---------------------------------------------------------------
# Flag 1: proof of RCE, readable by www-data.
# Flag 2: deploy's user.txt — home is 0750 so www-data cannot read it (forces lateral).
# Flag 3: root.txt, root-only.
RUN echo 'FLAG{rc3_c0mm4nd_1nj3ct10n}' > /var/www/forge/flag1.txt \
    && chown www-data:www-data /var/www/forge/flag1.txt && chmod 644 /var/www/forge/flag1.txt \
    && echo 'FLAG{lat3ral_www_t0_us3r}' > /home/deploy/user.txt \
    && chown deploy:deploy /home/deploy/user.txt && chmod 644 /home/deploy/user.txt \
    && chmod 750 /home/deploy \
    && echo 'FLAG{r00t_suid_path_hij4ck}' > /root/root.txt \
    && chmod 600 /root/root.txt

# --- sshd: password auth ON (deploy logs in after the lateral move),
#     root login OFF (root must be earned via the SUID hijack) -------------
RUN mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && ssh-keygen -A

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22 8000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

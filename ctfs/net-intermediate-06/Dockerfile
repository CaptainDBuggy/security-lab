# Relay — network/Linux boot2root CTF (intermediate+, second network box).
# Single container standing in for a compromised log-relay host: a public web app,
# an SSH service, a low-priv service account, and a CRON + world-writable-script
# priv-esc for root. Unlike Sentry, the root step is NOT a GTFOBins one-liner —
# `sudo -l` is a dead end and you must ENUMERATE your way to the cron misconfig.
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo cron findutils procps iproute2 ca-certificates less \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir flask==3.0.3

# --- low-priv foothold user (a "service account"); password is the one leaked
#     by the web app's exposed deploy env file. NOTE: svc has NO sudo rights —
#     `sudo -l` is intentionally a dead end. Root must be earned via cron. ---
RUN useradd -m -s /bin/bash svc \
    && echo 'svc:R3lay-Svc-2026!' | chpasswd

# --- THE PRIV-ESC: a root cron job runs /opt/relay/healthcheck.sh every minute.
#     The script is WORLD-WRITABLE (777, root-owned). svc can append a payload
#     that then executes as root on the next tick. This is a "writable cron
#     script" escalation — you have to find it by enumerating, not by sudo -l. ---
RUN mkdir -p /opt/relay
COPY healthcheck.sh /opt/relay/healthcheck.sh
RUN chown root:root /opt/relay/healthcheck.sh && chmod 777 /opt/relay/healthcheck.sh
COPY relay-health.cron /etc/cron.d/relay-health
RUN chown root:root /etc/cron.d/relay-health && chmod 644 /etc/cron.d/relay-health \
    && touch /var/log/relay-health.log && chmod 666 /var/log/relay-health.log

# --- flags (baked into the image at build time) ---
RUN echo 'FLAG{f00thold_svc_cr3d_r3us3}' > /home/svc/user.txt \
    && chown svc:svc /home/svc/user.txt && chmod 644 /home/svc/user.txt \
    && echo 'FLAG{r00t_cr0n_w0rld_writ4ble}' > /root/root.txt \
    && chmod 600 /root/root.txt

# --- sshd: password auth ON (leaked creds work), root login OFF (earn it) ---
RUN mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && ssh-keygen -A

COPY app.py /opt/app/app.py
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

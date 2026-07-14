# Sentry — network/Linux boot2root CTF.
# Single container that stands in for a compromised web host: a public web app,
# an SSH service, a low-priv foothold user, and a sudo misconfig for root.
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo findutils procps iproute2 ca-certificates less \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir flask==3.0.3

# --- low-priv foothold user; password is the one leaked by the web app ---
RUN useradd -m -s /bin/bash dev \
    && echo 'dev:Sup3rD3vPass!2026' | chpasswd

# --- THE PRIV-ESC: dev may run /usr/bin/find as root with no password.
#     find is a GTFOBins classic — it can -exec a shell, so this is instant root. ---
RUN echo 'dev ALL=(root) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/dev \
    && chmod 440 /etc/sudoers.d/dev

# --- flags (baked into the image at build time) ---
RUN echo 'FLAG{f00thold_ssh_cr3d_r3us3}' > /home/dev/user.txt \
    && chown dev:dev /home/dev/user.txt && chmod 644 /home/dev/user.txt \
    && echo 'FLAG{r00t_sudo_find_gtf0b1ns}' > /root/root.txt \
    && chmod 600 /root/root.txt

# --- sshd: password auth ON (so the leaked creds work), direct root login OFF
#     (root must be *earned* via priv-esc, not SSH'd into) ---
RUN mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && ssh-keygen -A

COPY app.py /opt/app/app.py
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

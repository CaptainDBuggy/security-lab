# Keyring — advanced network/Linux boot2root CTF (CTF 08).
# Chain that exercises the cracking toolchain + a NEW priv-esc class:
#   1) web LFI / path traversal  -> read a forgotten credential backup (a hash)
#   2) offline hash cracking     -> john/hashcat + rockyou recovers the password
#   3) SSH with cracked creds    -> foothold as 'keeper'
#   4) Linux CAPABILITIES        -> a cap_setuid binary = instant root (NOT SUID,
#      NOT sudo, NOT cron — a distinct pattern you find with getcap)
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo libcap2-bin \
        findutils procps iproute2 ca-certificates less \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir flask==3.0.3

# --- foothold user; password is 'chocolate' (the plaintext the leaked md5crypt
#     hash cracks to). keeper logs in over SSH once you've cracked it. ---
RUN useradd -m -s /bin/bash keeper \
    && echo 'keeper:chocolate' | chpasswd

# --- web app (runs as www-data) ------------------------------------------
RUN mkdir -p /var/www/keyring/pages /var/www/keyring/backup
COPY app.py               /var/www/keyring/app.py
COPY pages/welcome.txt    /var/www/keyring/pages/welcome.txt
COPY pages/changelog.txt  /var/www/keyring/pages/changelog.txt
COPY backup/users.bak     /var/www/keyring/backup/users.bak
RUN chown -R www-data:www-data /var/www/keyring \
    && chmod 644 /var/www/keyring/backup/users.bak

# --- THE PRIV-ESC: a copy of python with the cap_setuid capability set.
#     getcap -r / reveals it; cap_setuid lets os.setuid(0) succeed -> root.
#     (This is why LFI runs as www-data: shadow stays unreadable, and root must
#      be earned via the capability, not read straight off disk.) ---
RUN cp /usr/local/bin/python3.12 /usr/local/bin/pyadmin \
    && setcap cap_setuid+ep /usr/local/bin/pyadmin \
    && chmod 755 /usr/local/bin/pyadmin

# --- flags ---------------------------------------------------------------
# Flag 1: in the LFI-readable backup (see users.bak).
# Flag 2: keeper's user.txt (home 0750 -> www-data can't read it; crack+SSH needed).
# Flag 3: root.txt, root-only.
RUN echo 'FLAG{cr4ck3d_h4sh_ssh_l0gin}' > /home/keeper/user.txt \
    && chown keeper:keeper /home/keeper/user.txt && chmod 644 /home/keeper/user.txt \
    && chmod 750 /home/keeper \
    && echo 'FLAG{r00t_l1nux_c4p4b1l1t13s}' > /root/root.txt \
    && chmod 600 /root/root.txt

# --- sshd: password auth ON (cracked creds), root login OFF --------------
RUN mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && ssh-keygen -A

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22 8000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

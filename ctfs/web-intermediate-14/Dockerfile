FROM python:3.12-slim

# ping + nslookup so the "cover" commands are real.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping dnsutils \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# Three low-priv users, one per tool. Each flag file is readable ONLY by its own user,
# so one endpoint's RCE can't read another's flag — every flavour must be solved.
RUN useradd -r u1 && useradd -r u2 && useradd -r u3 \
 && printf 'FLAG{c0mm4nd_1nj3ct10n_15_rc3}\n'      > /flag1.txt \
 && printf 'FLAG{f1lt3r_byp4ss3d_w1th_IFS}\n'      > /flag2.txt \
 && printf 'FLAG{bl1nd_1nj3ct10n_f1l3_3xf1l}\n'    > /flag3.txt \
 && chown u1 /flag1.txt && chmod 400 /flag1.txt \
 && chown u2 /flag2.txt && chmod 400 /flag2.txt \
 && chown u3 /flag3.txt && chmod 400 /flag3.txt \
 && mkdir -p /app/public && chown u3 /app/public && chmod 755 /app/public

EXPOSE 5000
CMD ["python", "app.py"]

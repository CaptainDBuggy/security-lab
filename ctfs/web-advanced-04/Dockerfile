FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# Stage 3 target: a local secret the web layer never serves. Only reachable once
# you realise the fetcher will speak file:// as happily as http://.
RUN mkdir -p /opt/linkpeek/secrets && \
    printf 'db_backup_root_key: FLAG{ssrf_f1l3_sch3m3_l0cal_r34d}\n' > /opt/linkpeek/secrets/vault.txt

EXPOSE 5000
CMD ["python", "app.py"]

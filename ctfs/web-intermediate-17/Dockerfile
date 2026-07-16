FROM python:3.12-slim

# iputils-ping gives the maintenance "connectivity check" a real `ping` to run — the
# command-injection lesson rides on that shell call.
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# Stage-3 payoff: a flag file on disk, read via the command injection.
RUN printf 'FLAG{sh3ll_m3t4ch4r_c0mm4nd_1nj3ct10n}\n' > /flag3.txt

EXPOSE 5000
CMD ["python", "app.py"]

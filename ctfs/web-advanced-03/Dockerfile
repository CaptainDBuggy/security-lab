FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# Stage 2 target: a flag sitting on the filesystem, reachable only once you have
# code execution (there is no route that serves it).
RUN mkdir -p /srv && \
    printf 'FLAG{j1nj4_subcl4ss_rc3_pwn3d}\n' > /srv/flag_rce.txt

# Stage 3 target: a secret in the process environment. Overridable via compose,
# but present by default so `docker run` alone still ships the challenge.
ENV POSTPILOT_ROOT_SECRET="FLAG{rc3_3nv_var_l00t3d_gg}"

EXPOSE 5000
CMD ["python", "app.py"]

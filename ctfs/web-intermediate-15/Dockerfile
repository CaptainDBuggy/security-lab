FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# Upload spool (world-writable-ish for the app) and a PRIVATE dir the attachment route is
# never supposed to reach — flag4 lives here and is only reachable via ../ traversal.
RUN mkdir -p /app/uploads /app/private \
 && printf 'FLAG{p4th_tr4v3rs4l_arb1tr4ry_r34d}\n' > /app/private/flag4.txt

EXPOSE 5000
CMD ["python", "app.py"]

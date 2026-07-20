FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN printf 'FLAG{pyth0n_3v4l_c0d3_1nj3ct10n}\n' > /flag3.txt
EXPOSE 5000
CMD ["python", "app.py"]

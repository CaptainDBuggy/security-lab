# Official Playwright image: bundles a matching headless Chromium + all OS deps, so the
# moderator bot has a real browser with no fragile apt/font install step.
FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000
CMD ["python", "app.py"]

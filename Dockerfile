FROM python:3.11-slim

# set workdir
WORKDIR /app

# copy project files
COPY . /app

# install system dependencies for playwright + chromium
RUN apt-get update && \
    apt-get install -y wget gnupg curl git libglib2.0-0 libnss3 libgconf-2-4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libasound2 && \
    pip install --no-cache-dir -r requirements.txt && \
    python -m playwright install chromium && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

EXPOSE 5000

CMD ["python", "app.py"]

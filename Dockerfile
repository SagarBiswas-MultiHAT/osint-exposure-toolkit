FROM python:3.11-slim

RUN useradd -m osint
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R osint:osint /app

USER osint
VOLUME ["/app/output", "/app/config.yaml"]

ENTRYPOINT ["python", "main.py"]

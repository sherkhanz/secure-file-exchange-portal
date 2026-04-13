FROM python:3.12-slim

# Non-root user for least-privilege container execution
RUN useradd -m -u 1001 portaluser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=portaluser:portaluser main.py .

# Pre-create data dirs with correct ownership so volume mounts work
RUN mkdir -p /data/db /data/files && chown -R portaluser:portaluser /data

USER portaluser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]

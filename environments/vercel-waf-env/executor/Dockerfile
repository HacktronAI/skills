FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests flask

COPY server.py .

EXPOSE 8000

CMD ["python", "server.py"]


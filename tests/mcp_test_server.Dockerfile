FROM python:3.13-slim

RUN pip install --no-cache-dir mcp

COPY mcp_test_server.py /app/server.py

WORKDIR /app
EXPOSE 8000

CMD ["python3", "server.py", "--port", "8000"]

FROM python:3.14-slim

RUN adduser --system --no-create-home mcpguard

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY mcpguard/ mcpguard/
COPY setup.py .

RUN pip install --no-cache-dir . && rm -rf /root/.cache

USER mcpguard

EXPOSE 8080

ENTRYPOINT ["mcpguard"]
CMD ["proxy"]

FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY mcpguard/ mcpguard/

RUN pip install --no-cache-dir .

EXPOSE 8080

ENTRYPOINT ["mcpguard"]
CMD ["proxy"]

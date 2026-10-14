# A 的 Agent + AA 开发镜像。构建上下文为 agent-aa/（见 docker-compose.yml），不修改 A 的目录。
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .
WORKDIR /app
EXPOSE 8000
CMD ["agent-aa", "--help"]

# C 的 Streamlit Dashboard（可选，profile=dashboard）。构建上下文为 evaluation-dashboard/。
# C 尚未提供依赖清单，这里先装 Dashboard 与脚本用到的三个包；C 提供 requirements.txt 后改为安装它。
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install streamlit pandas requests
WORKDIR /app
COPY . .
EXPOSE 8501
CMD ["streamlit", "run", "dashboard/app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]

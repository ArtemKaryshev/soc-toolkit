# Образ для запуска веб-интерфейса в контейнере:
#   docker build -t soc-toolkit .
#   docker run --rm -p 127.0.0.1:8501:8501 -v soc_toolkit_home:/data soc-toolkit
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SOC_TOOLKIT_HOME=/data

RUN useradd --create-home --uid 1000 analyst
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY samples ./samples
RUN pip install .

USER analyst
VOLUME ["/data"]
EXPOSE 8501
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')"
# В контейнере слушаем все интерфейсы; наружу публикуйте порт только на 127.0.0.1 (см. пример выше)
CMD ["python", "-m", "streamlit", "run", "src/soc_toolkit/ui/app.py", "--server.address=0.0.0.0", \
     "--server.port=8501", "--server.headless=true", "--browser.gatherUsageStats=false"]

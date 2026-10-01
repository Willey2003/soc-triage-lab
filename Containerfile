FROM docker.io/library/python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SOC_DB=/data/cases.db
WORKDIR /srv
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY app app
COPY data data
COPY eval eval
COPY tests tests
COPY pyproject.toml .
RUN useradd -u 10001 -m soc && mkdir -p /data /srv/eval/results && chown -R soc /data /srv/eval/results
USER 10001
EXPOSE 8090
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8090"]

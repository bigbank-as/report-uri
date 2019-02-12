FROM python:3.6-slim

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=2s \
  CMD curl -f http://localhost:8080 || exit 1

ENV FLASK_APP=main.py

WORKDIR /opt/report-uri
COPY requirements.txt .

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/* && \
    pip install -r requirements.txt && \
    rm -f requirements.txt && \
    mkdir /var/log/python

CMD ["flask", "run", "-h","0.0.0.0", "-p","8080"]

COPY src /opt/report-uri

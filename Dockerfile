FROM python:3.9-slim-buster
RUN apt-get update && \
    apt-get install -y arp-scan nmap && \
    rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8080
CMD ["uvicorn", "--reload","--host", "0.0.0.0", "--port", "8000", "main:app"]

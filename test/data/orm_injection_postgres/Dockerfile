FROM python:3.10-slim

WORKDIR /app

COPY test/data/orm_injection_postgres/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

EXPOSE 80

CMD ["python", "app.py"]

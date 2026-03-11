FROM python:3.10-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY app.py .

EXPOSE 5000

CMD ["python", "app.py"]

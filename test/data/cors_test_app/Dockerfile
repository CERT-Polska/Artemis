FROM python:3.10-slim

WORKDIR /app

COPY ./test/data/cors_test_app/requirements.txt requirements.txt
RUN pip install -r requirements.txt

EXPOSE 80

CMD ["python", "app.py"]

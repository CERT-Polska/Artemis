FROM python:3.10-slim

WORKDIR /app

COPY ./test/data/redirect_reflect_app/requirements.txt requirements.txt
RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["python", "app.py"]

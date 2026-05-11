FROM python:3.11-slim

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY manage.py /app/
COPY src/ /app/src/
WORKDIR /app/

RUN python manage.py migrate
RUN python manage.py loaddata src/fixtures.json
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

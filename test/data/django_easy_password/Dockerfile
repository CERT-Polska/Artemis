FROM python:3.11.4-slim-buster

RUN pip install Django==5.0

RUN mkdir /usr/src/app/
COPY manage.py /usr/src/app/
COPY db.json /usr/src/app/
COPY djangoapp /usr/src/app/djangoapp/

WORKDIR /usr/src/app/

RUN python3 manage.py migrate
RUN python3 manage.py loaddata db.json

CMD ["python3", "manage.py", "runserver", "0.0.0.0:8000"]

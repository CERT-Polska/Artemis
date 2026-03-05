FROM python:3.11-slim
RUN pip install flask --no-cache-dir
COPY test/data/json_login_panel/app.py /app.py
CMD ["python", "/app.py"]

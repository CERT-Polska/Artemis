# Use an official Python base image
FROM python:3.10-slim

# Set working directory inside the container
WORKDIR /app

# Install Python dependencies
COPY ./test/data/dast_vuln_app/requirements.txt requirements.txt
RUN pip install -r requirements.txt

# Expose port Flask will run on
EXPOSE 5000

# Run the Flask app
CMD ["python", "app.py"]

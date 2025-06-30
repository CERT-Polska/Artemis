# Use an official Python base image
FROM python:3.10-slim

# Set working directory inside the container
WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir flask

# Expose port Flask will run on
EXPOSE 5000

# Run the Flask app
CMD ["python", "app.py"]

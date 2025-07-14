# Use official Python base image
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

COPY requirements.txt .

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*


RUN pip install --no-cache-dir -r requirements.txt


# Copy all files into container
COPY . .

# Install required packages
RUN pip install --no-cache-dir flask keystoneauth1 requests paramiko


# Expose Flask default port
EXPOSE 8000

# Start the app
CMD ["python", "app.py"]

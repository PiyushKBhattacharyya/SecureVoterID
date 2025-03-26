# Use an official Python image as base
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Install system dependencies (CMake, build tools)
RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    libopenblas-dev \
    liblapack-dev \
    libx11-dev \
    && rm -rf /var/lib/apt/lists/*
    
# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy the application files
COPY . .

# Expose the application port
EXPOSE 5000

# Load environment variables
ARG FLASK_APP
ARG FLASK_ENV
ARG FLASK_DEBUG
ARG DATABASE_URL
ARG SESSION_SECRET
ARG SESSION_LIFETIME
ARG FACE_SIMILARITY_THRESHOLD
ARG RATE_LIMIT_VERIFICATION
ARG RATE_LIMIT_REGISTRATION
ARG RATE_LIMIT_LOGIN
ARG QR_CODE_EXPIRY_HOURS
ARG LOG_LEVEL

# Load environments from .env
ENV DATABASE_URL=${DATABASE_URL}
ENV FLASK_APP=${FLASK_APP}
ENV FLASK_ENV=${FLASK_ENV}
ENV FLASK_DEBUG=${FLASK_DEBUG}
ENV SESSION_SECRET=${SESSION_SECRET}
ENV FACE_SIMILARITY_THRESHOLD=${FACE_SIMILARITY_THRESHOLD}
ENV SESSION_LIFETIME=${SESSION_LIFETIME}
ENV RATE_LIMIT_VERIFICATION=${RATE_LIMIT_VERIFICATION}
ENV RATE_LIMIT_REGISTRATION=${RATE_LIMIT_REGISTRATION}
ENV RATE_LIMIT_LOGIN=${RATE_LIMIT_LOGIN}
ENV QR_CODE_EXPIRY_HOURS=${QR_CODE_EXPIRY_HOURS}
ENV LOG_LEVEL=${LOG_LEVEL}

# Start the application (adjust as needed for your app)
CMD ["python", "main.py"]
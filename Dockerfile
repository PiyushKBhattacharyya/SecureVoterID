# Use an official Python image as base
FROM python:3.8

# Set the working directory
WORKDIR /app

# Install system dependencies (CMake, build tools)
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libglib2.0-0 \
    ffmpeg \
    cmake \
    build-essential \
    libopenblas-dev \
    liblapack-dev \
    libx11-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies in a virtual environment
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy the application files
COPY . .

# Expose the application port
EXPOSE 5000

# Ensure environment variables are loaded from Docker Compose
ENV DATABASE_URL=${DATABASE_URL}
ENV FLASK_APP=${FLASK_APP}
ENV FLASK_ENV=${FLASK_ENV}
ENV FLASK_DEBUG=${FLASK_DEBUG}
ENV SESSION_SECRET=${SESSION_SECRET}
ENV SESSION_LIFETIME=${SESSION_LIFETIME}
ENV FACE_SIMILARITY_THRESHOLD=${FACE_SIMILARITY_THRESHOLD}
ENV RATE_LIMIT_VERIFICATION=${RATE_LIMIT_VERIFICATION}
ENV RATE_LIMIT_REGISTRATION=${RATE_LIMIT_REGISTRATION}
ENV RATE_LIMIT_LOGIN=${RATE_LIMIT_LOGIN}
ENV QR_CODE_EXPIRY_HOURS=${QR_CODE_EXPIRY_HOURS}
ENV LOG_LEVEL=${LOG_LEVEL}

# Start the application
CMD ["python", "main.py"]
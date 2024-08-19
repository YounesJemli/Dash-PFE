# my_django_app/Dockerfile
FROM python:3.10
# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libpq-dev \
    && apt-get clean

# Create and set working directory
RUN mkdir /app
WORKDIR /app

# Copy project files
COPY . /app/

# Install project dependencies
RUN pip install --no-cache-dir -r requirements.txt
ENV DATABASE_HOST=postgres
ENV DATABASE_PORT=5432
ENV DATABASE_NAME=dash3s
ENV DATABASE_USER=postgres
ENV DATABASE_PASSWORD=139
# Run migrations and start the server
CMD ["sh", "-c", "python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]

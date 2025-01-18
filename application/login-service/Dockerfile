# Base Image
FROM python:3.10-slim

# Set environment variables from build arguments
ARG SECRET_KEY
ARG JWT_SECRET_KEY
ARG GOOGLE_CLIENT_ID
ARG GOOGLE_CLIENT_SECRET

ENV SECRET_KEY=$SECRET_KEY
ENV JWT_SECRET_KEY=$JWT_SECRET_KEY
ENV GOOGLE_CLIENT_ID=$GOOGLE_CLIENT_ID
ENV GOOGLE_CLIENT_SECRET=$GOOGLE_CLIENT_SECRET

# Copy application code
WORKDIR /app
COPY . /app

# Install dependencies
RUN pip install -r requirements.txt

# Expose port
EXPOSE 5000

# Run the app
CMD ["python", "app.py"]

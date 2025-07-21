FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./
# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o crs-server ./cmd/server

# Create a minimal production image
FROM docker:dind

# Install necessary tools
RUN apk add --no-cache \
    git \
    curl \
    wget \
    tar \
    gzip \
    unzip \
    python3 \
    py3-pip \
    bash \
    jq \
    ca-certificates \
    tzdata \
    build-base \
    openssh-client

# Set working directory
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/crs-server .

# Create necessary directories
RUN mkdir -p /app/tasks /app/logs

# Copy the entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
COPY .env /app/.env

# Set environment variables
ENV GIN_MODE=release
ENV CRS_TASK_DIR=/app/tasks
ENV CRS_LOG_DIR=/app/logs

# Expose the port
EXPOSE 7080

# Use the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]
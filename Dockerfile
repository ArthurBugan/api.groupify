# Use the Rust base image
FROM rust:bookworm as builder
# Set the working directory
WORKDIR /usr/src/myapp

# Copy the application code into the container
COPY . .

# Build the application
RUN cargo build --release

# Start a new stage
FROM debian:bookworm-slim

# Set the working directory
WORKDIR /usr/src/myapp

COPY .env /usr/src/myapp/.env

# Copy the built binary from the previous stage
COPY --from=builder /usr/src/myapp/target/release/api-groupify /usr/src/myapp/api-groupify

RUN apt-get update && apt install -y openssl

# Expose the port your application listens on
EXPOSE 3001

# Set the startup command
CMD ["./api-groupify"]

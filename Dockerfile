# ---- build stage ---- 
FROM alpine:3.22 AS build

# Install minimal build dependencies
RUN apk add --no-cache gcc musl-dev libcurl curl-dev

WORKDIR /src

# Copy your Cloudflare updater sources
COPY cloudflare-ddns.c cloudflare-ddns.h config.c config.h constant.h ./

# Build the DDNS updater dynamically
RUN gcc -O2 -o cloudflare-ddns cloudflare-ddns.c config.c -lcurl && \
    strip cloudflare-ddns

# ---- runtime stage ----
FROM alpine:3.22

# Install runtime dependencies
RUN apk add --no-cache libcurl ca-certificates

# Create a non-root user
RUN addgroup -g 1000 ddns && \
    adduser -D -s /bin/sh -u 1000 -G ddns ddns

# Copy the binary from build stage
COPY --from=build /src/cloudflare-ddns /usr/local/bin/cloudflare-ddns
COPY exec.sh /usr/local/bin/exec

# Copy config script to user's home directory
COPY config.sh /usr/local/bin/config.sh
RUN chown ddns:ddns /usr/local/bin/config.sh && chmod +x /usr/local/bin/config.sh

# Switch to non-root user
USER ddns

ENTRYPOINT ["/usr/local/bin/exec"]
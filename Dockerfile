# ---- build stage ---- 
FROM alpine:3.22 AS build

# Install minimal build dependencies
RUN apk add --no-cache gcc musl-dev libcurl curl-dev cjson-dev

WORKDIR /src

# Copy your Cloudflare updater sources
COPY cloudflare-ddns.c cloudflare-ddns.h  ./

# Build the DDNS updater dynamically
RUN gcc -O2 -o cloudflare-ddns cloudflare-ddns.c -lcurl -lcjson

# ---- runtime stage ----
FROM alpine:3.22

# Install runtime dependencies
RUN apk add --no-cache libcurl ca-certificates cjson

# Create a non-root user
RUN addgroup -g 1000 ddns && \
    adduser -D -s /bin/sh -u 1000 -G ddns ddns

# Copy the binary from build stage
COPY --from=build /src/cloudflare-ddns /usr/local/bin/cloudflare-ddns
COPY cloudflare-ddns.sh /usr/local/bin/cloudflare-ddns.sh

# Copy config script to user's home directory
RUN chown ddns:ddns /usr/local/bin/cloudflare-ddns.sh && chmod +x /usr/local/bin/cloudflare-ddns.sh

# Switch to non-root user
USER ddns

ENTRYPOINT ["/usr/local/bin/cloudflare-ddns.sh"]
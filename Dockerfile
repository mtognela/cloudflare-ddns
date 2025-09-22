# ---- build stage ---- 
FROM alpine:3.22 AS build

# install minimal build dependencies
RUN apk add --no-cache gcc musl-dev libcurl curl-dev

WORKDIR /src

# copy your Cloudflare updater sources
COPY cloudflare-ddns.c cloudflare-ddns.h config.h costant.h ./

# build the DDNS updater dynamically
RUN gcc -O2 -o cloudflare-ddns cloudflare-ddns.c -lcurl && \
    strip cloudflare-ddns

# ---- runtime stage ----
FROM alpine:3.22

# install runtime dependencies
RUN apk add --no-cache libcurl ca-certificates

# create a non-root user
RUN addgroup -g 1000 ddns && \
    adduser -D -s /bin/sh -u 1000 -G ddns ddns

# copy the binary
COPY --from=build /src/cloudflare-ddns /usr/local/bin/cloudflare-ddns

# switch to non-root user
USER ddns

ENTRYPOINT ["/usr/local/bin/cloudflare-ddns"]
#!/usr/bin/env sh
# Cloudflare Dynamic DNS Updater Configuration

# Cloudflare authentication
export CF_AUTH_EMAIL=your-email@example.com
export CF_AUTH_METHOD=token          # "global" for Global API Key or "token" for Scoped API Token
export CF_AUTH_KEY=your-api-key-or-token
export CF_ZONE_ID=your-zone-id

# DNS Records
export CF_RECORD_NAME_IPV4=yourdomain-ipv4.com
export CF_RECORD_NAME_IPV6=yourdomain-ipv6.com

# Record options
export CF_TTL=3600                   # Time in seconds DNS resolvers should cache the IP
export CF_PROXY=false                # "true" to enable Cloudflare proxy, "false" to disable

# Feature toggles
export CF_ENABLE_IPV4=1              # 1 to enable IPv4 updates, 0 to disable
export CF_ENABLE_IPV6=1              # 1 to enable IPv6 updates, 0 to disable

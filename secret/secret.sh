#!/usr/bin/env sh

alias dsc='docker secret create'

echo "your-email@example.com" | dsc CF_AUTH_EMAIL -
echo "token" | dsc CF_AUTH_METHOD -  # "global" for Global API Key or "token" for Scoped API Token
echo "your-api-key-or-token" | dsc CF_AUTH_KEY -
echo "your-zone-id" | dsc CF_ZONE_ID -

echo "yourdomain-ipv4.com" | dsc CF_RECORD_NAME_IPV4 - 
echo "yourdomain-ipv6.com" | dsc CF_RECORD_NAME_IPV6 - 

echo 3600 | dsc CF_TTL - # not proxied from 30s (Enterprise) or 60s (non-Enterprise) to 86400s. proxied only auto (auto equals to 300s)
echo "false" | dsc CF_PROXY - # "true" to enable Cloudflare proxy, "false" to disable

echo 1 | dsc CF_ENABLE_IPV4 - # 1 to enable IPv4 updates, 0 to disable
echo 1 | dsc CF_ENABLE_IPV6 - # 1 to enable IPv6 updates, 0 to disable
echo 1 | dsc CF_IS_ENTERPRISE - # 1 if you are an Cloudflare Enterprise Costumer, 0 if not
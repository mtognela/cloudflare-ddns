Set-Alias dsc "docker secret create"

# Cloudflare credentials
"your-email@example.com"    | dsc CF_AUTH_EMAIL -
"token"                     | dsc CF_AUTH_METHOD -  # "global" for Global API Key or "token" for Scoped API Token
"your-api-key-or-token"     | dsc CF_AUTH_KEY -
"your-zone-id"              | dsc CF_ZONE_ID -

# DNS record names
"yourdomain-ipv4.com"       | dsc CF_RECORD_NAME_IPV4 -
"yourdomain-ipv6.com"       | dsc CF_RECORD_NAME_IPV6 -

# TTL & Proxy settings
"3600"                      | dsc CF_TTL -        # TTL in seconds
"false"                     | dsc CF_PROXY -      # "true" to enable Cloudflare proxy, "false" to disable

# Feature toggles
"1"                         | dsc CF_ENABLE_IPV4 - # 1 to enable IPv4 updates, 0 to disable
"1"                         | dsc CF_ENABLE_IPV6 - # 1 to enable IPv6 updates, 0 to disable
"1"                         | dsc CF_IS_ENTERPRISE - # 1 if you are an Enterprise customer, 0 otherwise

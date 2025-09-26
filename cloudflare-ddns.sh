#!/usr/bin/env sh
# Cloudflare Dynamic DNS Updater Configuration
# Loads secrets from /run/secrets and exports them as environment variables

CF_SECRET_DIR=/run/secrets

# --- Cloudflare authentication ---
export CF_AUTH_EMAIL="$(cat $CF_SECRET_DIR/CF_AUTH_EMAIL)"
export CF_AUTH_METHOD="$(cat $CF_SECRET_DIR/CF_AUTH_METHOD)"   
export CF_AUTH_KEY="$(cat $CF_SECRET_DIR/CF_AUTH_KEY)"
export CF_ZONE_ID="$(cat $CF_SECRET_DIR/CF_ZONE_ID)"

# --- DNS Records ---
export CF_RECORD_NAME_IPV4="$(cat $CF_SECRET_DIR/CF_RECORD_NAME_IPV4)"
export CF_RECORD_NAME_IPV6="$(cat $CF_SECRET_DIR/CF_RECORD_NAME_IPV6)"

# --- Record options ---
export CF_TTL="$(cat $CF_SECRET_DIR/CF_TTL)"                   
export CF_PROXY="$(cat $CF_SECRET_DIR/CF_PROXY)"               

# --- Feature toggles ---
export CF_ENABLE_IPV4="$(cat $CF_SECRET_DIR/CF_ENABLE_IPV4)"   
export CF_ENABLE_IPV6="$(cat $CF_SECRET_DIR/CF_ENABLE_IPV6)"   
export CF_IS_ENTERPRISE="$(cat $CF_SECRET_DIR/CF_IS_ENTERPRISE)" 

# --- Run the updater ---
exec /usr/local/bin/cloudflare-ddns

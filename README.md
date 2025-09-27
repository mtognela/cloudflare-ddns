# Cloudflare Dynamic DNS Updater

A lightweight C program that automatically updates your Cloudflare DNS records with your current public IP address. Perfect for home servers, dynamic IP connections, or any situation where you need to keep your DNS records up to date.

## Features

- **Dual IP support** - Handles both IPv4 (A records) and IPv6 (AAAA records) simultaneously
- **Multiple IP detection services** - Redundant fallback services for reliable IP discovery
- **Flexible authentication** - Supports both Global API Keys and Scoped API Tokens
- **Comprehensive logging** - Detailed logging via syslog with stderr output for warnings/errors
- **Robust IP validation** - Uses `inet_pton()` for strict IPv4/IPv6 address validation
- **Intelligent updates** - Only updates DNS records when IP addresses actually change
- **Minimal resource usage** - Written in C with efficient memory management
- **JSON parsing** - Uses `cJSON` for strict parsing
- **Easy deployment** - Simple configuration via environment variables, perfect for crontab integration
- **Error resilience** - Graceful handling of network failures and API errors
- **Configurable parameters** - TTL, proxy settings, and record names easily customizable

The program follows suckless philosophy with a single-purpose design, minimal dependencies, and straightforward configuration through environment variables.


## Clone The Repo
Clone with `https`:
```bash
git clone https://github.com/mtognela/cloudflare-ddns.git
```
Or clone with `ssh`:
```bash
git clone git@github.com:mtognela/cloudflare-ddns.git
```

## Dependencies

This program requires the following libraries and development headers:

- **libcurl** - HTTP client library for making API requests to Cloudflare

- **cJSON**  - Ultralightweight JSON parser in ISO C 

- **Standard C library** - Core system functions including:
  - stdio.h     (ISO C standard input/output operations)
  - stdlib.h    (ISO C memory management, process control)
  - string.h    (ISO C string manipulation functions)
  - syslog.h    (POSIX system error logging)
  - unistd.h    (POSIX operating system API)
  - arpa/inet.h (POSIX internet operations)

### Installation of  Dependecies

**Debian/Ubuntu:**
```bash
sudo apt-get install libcurl4-openssl-dev build-essential libcjson-dev
```

**Fedora Linux:**
```bash
sudo dnf install libcurl-devel gcc make cjson
```

**Alpine Linux:**
```bash
apk add curl-dev build-base cjson-dev
```

**Arch Linux:**
```bash
pacman -S curl gcc cjson
``` 

## Build

```bash
gcc -o cloudflare-ddns cloudflare-ddns.c -lcurl -lcjson
```
## Configuration 

### Via env variables 

- `CF_AUTH_EMAIL` "your-email@example.com"
- `CF_AUTH_METHOD` "global" for Global API Key or "token" for Scoped API Token
- `CF_AUTH_KEY` "your-api-key-or-token"
- `CF_ZONE_ID` "your-zone-id"
- `CF_RECORD_NAME_IPV4` "yourdomain-ipv4.com"
- `CF_RECORD_NAME_IPV6` "yourdomain-ipv6.com"
- `CF_TTL` not 60-86400 for non-proxied, 30-86400 for Enterprise. proxied only auto (1 for auto)
- `CF_PROXY` "true" to enable Cloudflare proxy, "false" to disable
- `CF_ENABLE_IPV4` 1 to enable IPv4 updates, 0 to disable
- `CF_ENABLE_IPV6` 1 to enable IPv6 updates, 0 to disable
- `CF_IS_ENTERPRISE` 1 if you are an Cloudflare Enterprise Costumer, 0 if not

### Docker Secret 

For better security you can use `docker secret` via my **secret scripts**

Example wrapper script (`secret/secret.sh`):

```bash
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
```
Example wrapper script (`secret/secret.ps1`):

```ps1
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
```
#### How to run the secret script 
If you are on a Un*x system: 
```bash 
sudo sh secret/secret.sh 
```
Or on Windows with PowerShell as Administrator:
```ps1
.\secret\secret.ps1
```


### TTL Configuration Notes

- **Non-proxied records**: 60 seconds to 86400 seconds (1 day) for regular accounts, 30 seconds minimum for Enterprise
- **Proxied records**: Only "auto" is supported (equivalent to 300 seconds)
- Set `CF_TTL=1` for automatic TTL selection

### Getting Cloudflare Credentials

#### Option 1: API Token (Recommended)
1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Click "Create Token"
3. Use "Custom token" template
4. Set permissions:
   - Zone: Zone Settings:Read
   - Zone: DNS:Edit
5. Set zone resources to include your domain
6. Copy the token and use it as `CF_AUTH_KEY`
7. Set `CF_AUTH_METHOD` to `"token"`

#### Option 2: Global API Key
1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Find "Global API Key" section and click "View"
3. Copy the key and use it as `CF_AUTH_KEY`
4. Set `CF_AUTH_METHOD` to `"global"`
5. Set your Cloudflare email as `CF_AUTH_EMAIL`

#### Getting Zone ID
1. Go to your domain in Cloudflare Dashboard
2. In the right sidebar, find "Zone ID" and copy it

## Installation

```bash
sudo cp cloudflare-ddns /usr/local/bin/
sudo chmod +x /usr/local/bin/cloudflare-ddns
```

2. Test the program manually:
```bash
# Load all env var 
exec /usr/local/bin/cloudflare-ddns
```

Here’s an improved and more complete version of your **Docker Deploying** section, with clearer instructions and added details:

---

## Docker Deployment

You can run the **Cloudflare DDNS Updater** inside a lightweight Docker container using a multi-stage build for efficiency.

### Build & Run with Docker

#### 1. Build the Docker image

Run the following command inside the project directory (where the `Dockerfile` is located):

```bash
docker build -t cloudflare-ddns .
```

#### 2. Run the container

After building the image, start a container:

```bash
docker run -d \
  --name cloudflare-ddns \
  -e CF_AUTH_EMAIL=your-email@example.com \
  -e CF_AUTH_METHOD=token \
  -e CF_AUTH_KEY=your-api-key-or-token \
  -e CF_ZONE_ID=your-zone-id \
  -e CF_RECORD_NAME_IPV4=yourdomain-ipv4.com \
  -e CF_RECORD_NAME_IPV6=yourdomain-ipv6.com \
  -e CF_TTL=1 \
  -e CF_PROXY=true \
  -e CF_ENABLE_IPV4=1 \
  -e CF_ENABLE_IPV6=1 \
  -e CF_IS_ENTERPRISE=0 \
  cloudflare-ddns
```

### Deploy with Docker Compose

#### Run the service

```bash
docker compose up -d
```

#### Stop the service

```bash
docker compose down
```

### Dockerfile Overview

* **Build stage**: Uses Alpine Linux to compile the DDNS updater with libcurl.
* **Runtime stage**: Uses a minimal Alpine image with only `libcurl` and `ca-certificates` for HTTPS support and `cjson` for json parsing .
* The binary is stripped and copied to the runtime image for a small footprint (~7-8 MB).
* Runs as a **non-root user** for security.

### Using Cron in Docker

If you want the updater to run at regular intervals inside the container:

1. Add a `crontab` file to your project:

```cron
*/5 * * * * /usr/local/bin/cloudflare-ddns.sh >/proc/1/fd/1 2>/proc/1/fd/2
```

2. Modify your Dockerfile to install `cronie` and run cron:

```dockerfile
RUN apk add --no-cache cronie
COPY crontab /etc/crontabs/ddns
CMD ["crond", "-f", "-d", "8"]
```

This will run the DDNS updater every 5 minutes and log output to Docker logs.

### Docker Logs

View logs of the running container:

```bash
docker logs -f cloudflare-ddns
```

All DDNS updates and errors will be visible in real-time.

## Setting Up Crontab

To automatically update your DNS records at regular intervals, set up a cron job:

1. Open the crontab editor:
```bash
crontab -e
```

2. Add one of the following lines based on your preferred update frequency:

### Every 5 minutes (recommended for dynamic IPs)
```bash
*/5 * * * * /usr/local/bin/cloudflare-ddns.sh >/dev/null 2>&1
```

### Every 15 minutes
```bash
*/15 * * * * /usr/local/bin/cloudflare-ddns.sh >/dev/null 2>&1
```

### Every hour
```bash
0 * * * * /usr/local/bin/cloudflare-ddns.sh >/dev/null 2>&1
```

### Every 6 hours
```bash
0 */6 * * * /usr/local/bin/cloudflare-ddns.sh >/dev/null 2>&1
```

3. Save and exit the editor. The cron daemon will automatically pick up the changes.

## Logging

The program logs to syslog with the identifier "CF-DDNS-U". To view the logs:

### View recent logs
```bash
tail -f /var/log/syslog | grep "CF-DDNS-U"
```

### View all DDNS logs
```bash
journalctl -t "CF-DDNS-U"
```

### On systems using rsyslog, you can also check
```bash
grep "CF-DDNS-U" /var/log/messages
```

## Return Codes

- `0` (EXIT_SUCCESS): Success (IP updated or no change needed)
- `1` (EXIT_FAILURE): Error (DNS record not found, API error, configuration error, or update failed)

## Troubleshooting

### Common Issues

1. **Compilation errors**
   - Fix the bugs listed in the "Known Issues" section above
   - Ensure all dependencies are installed

2. **"Record does not exist" error**
   - Make sure the DNS record exists in Cloudflare Dashboard
   - Verify `CF_RECORD_NAME_IPV4`/`CF_RECORD_NAME_IPV6` matches exactly (including subdomain)

3. **Authentication errors**
   - Double-check your API token/key and email
   - Ensure token has proper permissions
   - Verify `CF_AUTH_METHOD` is set correctly ("token" or "global")

4. **"Failed to get current IP" error**
   - Check internet connectivity
   - Verify libcurl is properly installed
   - Some networks may block the IP detection services

5. **Permission errors**
   - Ensure the binary has execute permissions
   - Check that cron has permission to run the program

6. **TTL validation errors**
   - Ensure TTL is within valid range (60-86400 for non-proxied, 30-86400 for Enterprise)
   - Use CF_TTL=1 for automatic TTL

## License

This program is free software licensed under the GNU General Public License v2.0. See the source code for full license text.

## Author

Copyright (C) 2025  Mattia Tognela

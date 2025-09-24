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
- **JSON parsing** - Custom regex-based JSON extraction without heavy dependencies
- **Easy deployment** - Simple configuration via environment variables, perfect for crontab integration
- **Error resilience** - Graceful handling of network failures and API errors
- **Configurable parameters** - TTL, proxy settings, and record names easily customizable

The program follows suckless philosophy with a single-purpose design, minimal dependencies, and straightforward configuration through environment variables.

## Dependencies

This program requires the following libraries and development headers:

- **libcurl** - HTTP client library for making API requests to Cloudflare

- **Standard C library** - Core system functions including:
  - stdio.h     (ISO C standard input/output operations)
  - stdlib.h    (ISO C memory management, process control)
  - string.h    (ISO C string manipulation functions)
  - syslog.h    (POSIX system error logging)
  - unistd.h    (POSIX operating system API)
  - regex.h     (POSIX regex library)
  - arpa/inet.h (POSIX internet operations)

### Installation Examples

**Debian/Ubuntu:**
```sh
sudo apt-get install libcurl4-openssl-dev build-essential
```

**RHEL/CentOS/Fedora:**
```sh
sudo yum install libcurl-devel gcc make
# or on newer versions:
sudo dnf install libcurl-devel gcc make
```

**Alpine Linux:**
```sh
apk add curl-dev build-base
```

## Build Instructions

### Ubuntu/Debian
```sh
# Install dependencies
sudo apt update
sudo apt install build-essential libcurl4-openssl-dev

# Clone or download the source code
# Compile the program
gcc -o cloudflare-ddns cloudflare-ddns.c -lcurl
```

### CentOS/RHEL/Fedora
```sh
# Install dependencies
sudo yum install gcc make libcurl-devel
# OR for newer versions:
sudo dnf install gcc make libcurl-devel

# Compile the program
gcc -o cloudflare-ddns cloudflare-ddns.c -lcurl
```

### Alpine Linux
```sh
# Install dependencies
sudo apk add build-base curl-dev

# Compile the program
gcc -o cloudflare-ddns cloudflare-ddns.c -lcurl
```

## Known Issues & Required Fixes

**The current code has several bugs that must be fixed before use:**


3. **Header File Inconsistencies**: The header file function signatures don't match the implementation:
   - `verify_enable_ip()` should be `verify_1_0()`
   - `verify_ttl()` signature differs between header and implementation
   - `format_ttl()` function is missing from header file

4. **Memory Management**: The `format_ttl()` function returns a string literal in some cases but allocated memory in others, which can cause issues with `free()` calls.

**These bugs must be fixed before the program will compile and run correctly.**

## Configuration

Configuration is handled via environment variables using the wrapper script.

Example wrapper script (`cloudflare-ddns.sh`):

```sh
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
export CF_TTL=3600                   # not proxied: 30s (Enterprise) or 60s (non-Enterprise) to 86400s. proxied: only auto (equals 300s)
export CF_PROXY=false                # "true" to enable Cloudflare proxy, "false" to disable

# Feature toggles
export CF_ENABLE_IPV4=1              # 1 to enable IPv4 updates, 0 to disable
export CF_ENABLE_IPV6=1              # 1 to enable IPv6 updates, 0 to disable
export CF_IS_ENTERPRISE=0            # 1 if you are a Cloudflare Enterprise Customer, 0 if not  

exec /usr/local/bin/cloudflare-ddns
```

Make the script executable:

```sh
chmod +x cloudflare-ddns.sh
./cloudflare-ddns.sh
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

1. After compilation (and fixing the bugs), copy the binary to a system location:
```sh
sudo cp cloudflare-ddns /usr/local/bin/
sudo cp cloudflare-ddns.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/cloudflare-ddns
sudo chmod +x /usr/local/bin/cloudflare-ddns.sh
```

2. Test the program manually (after fixing the bugs):
```sh
/usr/local/bin/cloudflare-ddns.sh
```

## Docker

You can run the Cloudflare DDNS Updater in a lightweight Docker container using a multi-stage build. **Note: The code bugs must be fixed before building the Docker image.**

### Build & Run

#### 1. Build the Docker image

```sh
docker build -t cloudflare-ddns .
```
#### 2. Run the container with the wrapper script 

```sh
docker run -d \
  --name cloudflare-ddns \
  cloudflare-ddns
```

#### 3. Run the container with environment variables

```sh
docker run -d \
  --name cloudflare-ddns \
  -e CF_AUTH_EMAIL=your-email@example.com \
  -e CF_AUTH_METHOD=token \
  -e CF_AUTH_KEY=your-api-token \
  -e CF_ZONE_ID=your-zone-id \
  -e CF_RECORD_NAME_IPV4=yourdomain.com \
  -e CF_RECORD_NAME_IPV6=yourdomain.com \
  -e CF_TTL=3600 \
  -e CF_PROXY=false \
  -e CF_ENABLE_IPV4=1 \
  -e CF_ENABLE_IPV6=0 \
  -e CF_IS_ENTERPRISE=0 \
  cloudflare-ddns
```

### Dockerfile Overview

* **Build stage**: Uses Alpine Linux to compile the DDNS updater with libcurl.
* **Runtime stage**: Uses a minimal Alpine image with only `libcurl` and `ca-certificates` for HTTPS support.
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
```sh
crontab -e
```

2. Add one of the following lines based on your preferred update frequency:

### Every 5 minutes (recommended for dynamic IPs)
```sh
*/5 * * * * /usr/local/bin/cloudflare-ddns.sh >/dev/null 2>&1
```

### Every 15 minutes
```sh
*/15 * * * * /usr/local/bin/cloudflare-ddns.sh >/dev/null 2>&1
```

### Every hour
```sh
0 * * * * /usr/local/bin/cloudflare-ddns.sh >/dev/null 2>&1
```

### Every 6 hours
```sh
0 */6 * * * /usr/local/bin/cloudflare-ddns.sh >/dev/null 2>&1
```

3. Save and exit the editor. The cron daemon will automatically pick up the changes.

## Logging

The program logs to syslog with the identifier "CF-DDNS-U". To view the logs:

### View recent logs
```sh
tail -f /var/log/syslog | grep "CF-DDNS-U"
```

### View all DDNS logs
```sh
journalctl -t "CF-DDNS-U"
```

### On systems using rsyslog, you can also check
```sh
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

### Manual Testing

Run the wrapper script manually to see detailed output:
```sh
./cloudflare-ddns.sh
```

For more verbose debugging, check the syslog in real-time while running the program:
```sh
tail -f /var/log/syslog | grep "CF-DDNS-U" &
./cloudflare-ddns.sh
```

## Security Considerations

* Protect your wrapper script containing secrets (consider using file permissions 700)
* Prefer API Tokens over Global API Keys (more restrictive permissions)
* Regularly rotate credentials
* Run with least privilege (non-root user when possible)
* Store sensitive configuration outside of version control

## License

This program is free software licensed under the GNU General Public License v2.0. See the source code for full license text.

## Author

Copyright (C) 2025  Mattia Tognela
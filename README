# Cloudflare Dynamic DNS Updater

A lightweight C program that automatically updates your Cloudflare DNS records with your current public IP address. Perfect for home servers, dynamic IP connections, or any situation where you need to keep your DNS records up to date.

## Features

- Written in C for minimal resource usage
- Multiple IP detection services for reliability
- Supports both Global API Keys and Scoped API Tokens
- Comprehensive logging via syslog
- IPv4 address validation
- Easy crontab integration
- Error handling and recovery

## Dependencies

- libcurl (for HTTP requests)
- POSIX regex library (usually included with libc)
- Standard C library

## Build Instructions

### Ubuntu/Debian
```bash
# Install dependencies
sudo apt update
sudo apt install build-essential libcurl4-openssl-dev

# Clone or download the source code
# Compile the program
gcc -o cloudflare-ddns cloudflare-ddns.c -lcurl
```

### CentOS/RHEL/Fedora
```bash
# Install dependencies
sudo yum install gcc make libcurl-devel
# OR for newer versions:
sudo dnf install gcc make libcurl-devel

# Compile the program
gcc -o cloudflare-ddns cloudflare-ddns.c -lcurl
```

### Alpine Linux
```bash
# Install dependencies
sudo apk add build-base curl-dev

# Compile the program
gcc -o cloudflare-ddns cloudflare-ddns.c -lcurl
```

## Configuration

1. Edit the `config.h` file with your Cloudflare credentials and settings:

```c
#define AUTH_EMAIL "your-email@example.com"
#define AUTH_METHOD "token"  // "global" for Global API Key or "token" for Scoped API Token
#define AUTH_KEY "your-api-key-or-token"
#define ZONE_IDENTIFIER "your-zone-id"
#define RECORD_NAME "subdomain.yourdomain.com"
#define TTL 3600
#define PROXY "false"  // "true" to enable Cloudflare proxy, "false" to disable
#define SITE_NAME "Your Site Name"
```

### Getting Cloudflare Credentials

#### Option 1: API Token (Recommended)
1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Click "Create Token"
3. Use "Custom token" template
4. Set permissions:
   - Zone: Zone Settings:Read
   - Zone: DNS:Edit
5. Set zone resources to include your domain
6. Copy the token and use it as `AUTH_KEY`
7. Set `AUTH_METHOD` to `"token"`

#### Option 2: Global API Key
1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Find "Global API Key" section and click "View"
3. Copy the key and use it as `AUTH_KEY`
4. Set `AUTH_METHOD` to `"global"`
5. Set your Cloudflare email as `AUTH_EMAIL`

#### Getting Zone ID
1. Go to your domain in Cloudflare Dashboard
2. In the right sidebar, find "Zone ID" and copy it

## Installation

1. After compilation, copy the binary to a system location:
```bash
sudo cp cloudflare-ddns /usr/local/bin/
sudo chmod +x /usr/local/bin/cloudflare-ddns
```

2. Test the program manually:
```bash
/usr/local/bin/cloudflare-ddns
```

## Setting Up Crontab

To automatically update your DNS records at regular intervals, set up a cron job:

1. Open the crontab editor:
```bash
crontab -e
```

2. Add one of the following lines based on your preferred update frequency:

### Every 5 minutes (recommended for dynamic IPs)
```bash
*/5 * * * * /usr/local/bin/cloudflare-ddns >/dev/null 2>&1
```

### Every 15 minutes
```bash
*/15 * * * * /usr/local/bin/cloudflare-ddns >/dev/null 2>&1
```

### Every hour
```bash
0 * * * * /usr/local/bin/cloudflare-ddns >/dev/null 2>&1
```

### Every 6 hours
```bash
0 */6 * * * /usr/local/bin/cloudflare-ddns >/dev/null 2>&1
```

3. Save and exit the editor. The cron daemon will automatically pick up the changes.

## Logging

The program logs to syslog with the identifier "DDNS Updater". To view the logs:

### View recent logs
```bash
tail -f /var/log/syslog | grep "DDNS Updater"
```

### View all DDNS logs
```bash
journalctl -t "DDNS Updater"
```

### On systems using rsyslog, you can also check
```bash
grep "DDNS Updater" /var/log/messages
```

## Return Codes

- `0`: Success (IP updated or no change needed)
- `1`: Error (DNS record not found, API error, or update failed)
- `2`: Failed to get current IP address

## Troubleshooting

### Common Issues

1. **"Record does not exist" error**
   - Make sure the DNS record exists in Cloudflare Dashboard
   - Verify `RECORD_NAME` matches exactly (including subdomain)

2. **Authentication errors**
   - Double-check your API token/key and email
   - Ensure token has proper permissions
   - Verify `AUTH_METHOD` is set correctly

3. **"Failed to find a valid IP" error**
   - Check internet connectivity
   - Verify libcurl is properly installed
   - Some networks may block the IP detection services

4. **Permission errors**
   - Ensure the binary has execute permissions
   - Check that cron has permission to run the program

### Manual Testing

Run the program manually to see detailed output:
```bash
./cloudflare-ddns
```

For more verbose debugging, you can also check the syslog in real-time while running the program.

## Security Considerations

- Keep your `config.h` file secure and don't share it
- Consider using API tokens instead of Global API Keys for better security
- Regularly rotate your API credentials
- Ensure proper file permissions on the compiled binary

## License

This program is free software licensed under the GNU General Public License v2.0. See the source code for full license text.

## Author

Copyright (C) 2025  Mattia Tognela

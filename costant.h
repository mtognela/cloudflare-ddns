/*
    Cloudflare Dynamic DNS Updater
    Copyright (C) 2025  Mattia Tognela

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, see <https://www.gnu.org/licenses/>.
*/

#ifndef CONSTANT_H
#define CONSTANT_H

#define MAX_IP_SIZE_V4 16
#define MAX_IP_SIZE_V6 40
#define MAX_RECORD_ID_SIZE 64
#define H_BFF 128
#define BFF 256
#define D_BFF 512

#define IPV4_RECORD "A"
#define IPV4_TYPE 4
#define IPV6_RECORD "AAAA"
#define IPV6_TYPE 6

#define INCLUDE_JSON 1
#define NO_JSON 0

#define CLOUDFLARE_API_DNS_QUERY "https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=%s&name=%s"
#define CLOUDFLARE_API_DNS_RECORD "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s"

#define JSON_QUETY_FORMAT "{\"type\":\"%s\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":%d,\"proxied\":%s}"

#define LOG_ID "CF-DDNS-U"

#endif

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

#ifndef CONFIG_H
#define CONFIG_H

#define AUTH_EMAIL       "your-email@example.com"
#define AUTH_METHOD      "token"  /* "global" for Global API Key or "token" for Scoped API Token */
#define AUTH_KEY         "your-api-key-or-token"
#define ZONE_IDENTIFIER  "your-zone-id"
#define RECORD_NAME_IPV4 "yourdomain-ipv4.com"
#define RECORD_NAME_IPV6 "yourdomain-ipv6.com"
#define TTL               3600    /* how long DNS resolvers should cache the IP address    */
#define PROXY             "false" /* "true" to enable Cloudflare proxy, "false" to disable */
#define ENABLE_IPV4       1       /* 1 to enable ipv4 0 to disable it */
#define ENABLE_IPV6       1       /* 1 to enable ipv6 0 to disable it */

#endif
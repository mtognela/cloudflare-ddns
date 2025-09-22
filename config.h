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
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA. 
*/

#ifndef CONFIG_H
#define CONFIG_H

#define AUTH_EMAIL ""
#define AUTH_METHOD "token"  // "global" for Global API Key or "token" for Scoped API Token
#define AUTH_KEY ""
#define ZONE_IDENTIFIER ""
#define RECORD_NAME_IPV4 ""
#define RECORD_NAME_IPV6 ""
#define TTL 3600
#define PROXY "false"
#define ENABLE_IPV4 1
#define ENABLE_IPV6 1 

#endif
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

#include <stddef.h>

/* Configuration struct */
typedef struct {
    const char *auth_email;
    const char *auth_method;
    const char *auth_key;
    const char *zone_id;
    const char *record_name_ipv4;
    const char *record_name_ipv6;
    const char *proxy; 
    const int  *ttl;      
    const int  *enable_ipv4; 
    const int  *enable_ipv6; 
} Config_t;

/**
 * Load configuration from environment variables.
 * Exits program if required values are missing.
 */
int load_config(Config_t *cfg);

#endif

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int load_config(Config_t *cfg) {
    cfg->auth_email       =                   getenv("CF_AUTH_EMAIL");
    cfg->auth_method      =                   getenv("CF_AUTH_METHOD");
    cfg->auth_key         =                   getenv("CF_AUTH_KEY");
    cfg->zone_id          =                   getenv("CF_ZONE_ID");
    cfg->record_name_ipv4 =                   getenv("CF_RECORD_NAME_IPV4");
    cfg->record_name_ipv6 =                   getenv("CF_RECORD_NAME_IPV6");
    cfg->proxy            =                   getenv("CF_PROXY");
    cfg->ttl              =              atoi(getenv("CF_TTL"));
    cfg->enable_ipv4      =              atoi(getenv("CF_ENABLE_IPV4"));
    cfg->enable_ipv6      =              atoi(getenv("CF_ENABLE_IPV6"));

    if (!cfg->auth_email || !cfg->auth_method || !cfg->auth_key || !cfg->zone_id) {
        fprintf(stderr, "Missing required environment variables! Check your config.sh\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

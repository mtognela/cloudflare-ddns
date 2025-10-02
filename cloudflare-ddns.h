/*
    Cloudflare Dynamic DNS Updater
    Copyright (C) 2025  Mattia Tognela

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, see <https://www.gnu.org/licenses/>.
*/

#ifndef CLOUDFLARE_DDNS_H
#define CLOUDFLARE_DDNS_H

#include <stddef.h> 

/**
 * @struct Response_t
 * @brief Stores response data from a libcurl HTTP request.
 *
 * Holds a dynamically allocated buffer containing the full HTTP response
 * and its length.
 */
typedef struct {
    char *data;   /**< Pointer to buffer holding the response data */
    size_t size;  /**< Current size of the response buffer in bytes */
} Response_t;

/**
 * @struct Config_t
 * @brief Configuration settings for Cloudflare DNS updates.
 *
 * Contains API authentication data, zone/record details, and feature flags.
 */
typedef struct {
    const char *auth_email;       /**< Cloudflare account email (for key auth) */
    const char *auth_method;      /**< Authentication method ("token" or "key") */
    const char *auth_key;         /**< API token or Global API key */
    const char *zone_id;          /**< Cloudflare Zone ID */
    const char *record_name_ipv4; /**< DNS record name for IPv4 */
    const char *record_name_ipv6; /**< DNS record name for IPv6 */
    const char *proxy;            /**< Proxy setting: "true" or "false" */
          int  ttl;               /**< DNS record TTL (in seconds) */
          int  enable_ipv4;       /**< Enable IPv4 updates (1 = enabled) */
          int  enable_ipv6;       /**< Enable IPv6 updates (1 = enabled) */
          int  is_enterprise;     /**< Set 1 if you are an Enterprise Clouflare Costumer 0 if not */
} Config_t;

static inline Config_t* new_Config_t() {
    Config_t *config = calloc(1, sizeof(Config_t));
    return config;
}

/**
 * @brief libcurl write callback.
 *
 * Called by libcurl when receiving data. Appends data into a Response_t buffer.
 *
 * @param contents Pointer to the received chunk.
 * @param size Size of each element (always 1 for HTTP).
 * @param nmemb Number of elements received.
 * @param userdata Pointer to a Response_t structure.
 * @return Number of bytes processed, or 0 on failure (stops transfer).
 */
static size_t write_callback(char *contents, size_t size, size_t nmemb, void *userdata);

/**
 * @brief Logs a message via syslog and optionally stderr.
 *
 * Messages with priority LOG_WARNING or higher are mirrored to stderr.
 *
 * @param priority Syslog priority (LOG_INFO, LOG_WARNING, LOG_ERR, etc.).
 * @param message Null-terminated string to log.
 */
static void log_message(int priority, const char *message);

/**
 * @brief Validates an IPv4 address string.
 *
 * Uses inet_pton() to check format.
 *
 * @param ip IPv4 string.
 * @return 1 if valid, 0 otherwise.
 */
static int is_valid_ipv4(const char *ip);

/**
 * @brief Validates an IPv6 address string.
 *
 * Uses inet_pton() to check format.
 *
 * @param ip IPv6 string.
 * @return 1 if valid, 0 otherwise.
 */
static int is_valid_ipv6(const char *ip);

/**
 * @brief Retrieves the current public IP address.
 *
 * Queries one or more IP service URLs until a valid address is found.
 *
 * @param ip_buffer Buffer to store the result.
 * @param buffer_size Size of ip_buffer in bytes.
 * @param ip_services NULL-terminated array of service URLs.
 * @param ip_type IPV4_TYPE or IPV6_TYPE.
 * @return 0 on success, -1 on failure.
 */
int get_current_ip(char *ip_buffer, size_t buffer_size, const char* const ip_services[], int ip_type);

/**
 * @brief Extracts a string value from a JSON object by key.
 *
 * Uses cJSON to parse the JSON string and retrieve the value associated
 * with the given key. Returns a newly allocated copy of the value.
 *
 * @param json JSON text (null-terminated string).
 * @param key  Key to search for (case-sensitive).
 * @return Newly allocated string containing the value, or NULL if not found.
 *         Caller must free() the returned string.
 */
char* extract_json_value(const char *json, const char *key);

/**
 * @brief Prepares HTTP headers for Cloudflare API requests.
 *
 * Adds authentication headers (X-Auth-Key or Authorization: Bearer)
 * and optionally includes Content-Type: application/json.
 *
 * @param include_json 1 to include JSON header, 0 otherwise.
 * @param config Pointer to Config_t containing auth data.
 * @return Pointer to a curl_slist of headers. Must free with curl_slist_free_all().
 */
static struct curl_slist* prepare_headers(int include_json, const Config_t *config);

/**
 * @brief Fetches an existing DNS record from Cloudflare.
 *
 * Retrieves the record’s IP address and Cloudflare record ID.
 *
 * @param old_ip Buffer to store the record’s current IP.
 * @param record_id Buffer to store the record ID.
 * @param record_name Record name (e.g., "example.com").
 * @param record_type Record type ("A" or "AAAA").
 * @param config Pointer to Config_t with API details.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on error.
 */
int get_dns_record(
    char *old_ip, 
    char *record_id, 
    const char *record_name, 
    const char *record_type,
    const Config_t *config);

/* to document */
static int format_ttl(int ttl, const char *proxy, char *out, size_t out_size);

/**
 * @brief Updates a DNS record in Cloudflare.
 *
 * Sends a PATCH request to update the record with a new IP.
 *
 * @param current_ip New IP address.
 * @param record_id Cloudflare record ID.
 * @param record_name DNS record name.
 * @param record_type Record type ("A" or "AAAA").
 * @param config Pointer to Config_t with API details.
 * @return EXIT_SUCCESS if update succeeded, EXIT_FAILURE otherwise.
 */
int update_dns_record(
    const char *current_ip, 
    const char *record_id, 
    const char *record_name, 
    const char *record_type,
    const Config_t *config);

/**
 * @brief Retrieves an integer value from an environment variable.
 *
 * Reads the value of an environment variable, converts it to an integer, 
 * and stores it in the provided output pointer.
 *
 * @param name Name of the environment variable.
 * @param out Pointer to store the converted integer value.
 * @return 1 if the variable exists and conversion succeeds, 0 otherwise.
 */
static int getenv_int(const char *name, int *out);

/**
 * @brief Validates whether an enable/disable flag is valid.
 *
 * Checks if the given flag is either 0 (disabled) or 1 (enabled).
 *
 * @param enable_ip Integer flag representing enable/disable.
 * @return 1 if valid, 0 otherwise.
 */
static int verify_enable_ip(int enable_ip);

/**
 * @brief Validates a TTL (Time-To-Live) value.
 *
 * Accepts a value of 1 (representing "auto") or checks if the TTL 
 * falls within the predefined range [MIN_TTL, MAX_TTL].
 *
 * @param ttl TTL value to validate.
 * @return 1 if the TTL is valid, 0 otherwise.
 */
static int verify_ttl(int ttl, int is_enterprise);

/**
 * @brief Verifies the validity of a configuration structure.
 *
 * Ensures that all required fields in the Config_t structure are set, 
 * and that both TTL and enable flags (IPv4, IPv6) are valid.
 *
 * @param config Pointer to the Config_t structure to verify.
 * @return EXIT_SUCCESS if configuration is valid, EXIT_FAILURE otherwise.
 */
static int verify_Config_t(Config_t *config);

/**
 * @brief Loads configuration from environment variables.
 *
 * Reads required settings from the environment. Exits program if
 * critical values are missing.
 *
 * @param cfg Pointer to Config_t to populate.
 * @return 0 on success, nonzero on error.
 */
int load_config(Config_t *cfg);

/**
 * @brief Checks and updates a DNS record if the public IP has changed.
 *
 * Retrieves the current public IP, compares it to the DNS record,
 * and updates the record if necessary.
 *
 * @param record_name Record name.
 * @param record_type Record type ("A" or "AAAA").
 * @param current_ip Buffer to store the current public IP.
 * @param ip_size Size of current_ip buffer.
 * @param old_ip Buffer to store the record’s previous IP.
 * @param record_id Buffer to store the record ID.
 * @param ip_services Array of IP service URLs.
 * @param ip_version IPV4_TYPE or IPV6_TYPE.
 * @param config Pointer to Config_t with API details.
 * @return EXIT_SUCCESS if record is updated or already current, EXIT_FAILURE otherwise.
 */
static int update_ip_record(
    const char *record_name,
    const char *record_type,
    char *current_ip,
    size_t ip_size,
    char *old_ip,
    char *record_id,
    const char *const ip_services[],
    int ip_version,
    Config_t *config);

#endif

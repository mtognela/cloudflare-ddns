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
#include <curl/curl.h>
#include <arpa/inet.h>
#include <regex.h>
#include <syslog.h>
#include <unistd.h>
#include "cloudflare-ddns.h"
#include "costant.h"
#include "config.h"

/* 
    IP services to try for IPv4 
*/
static const char *const ip_services_v4[] = {
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    NULL
};

/* 
    IP services to try for IPv6
*/
static const char *const ip_services_v6[] = {
    "https://api6.ipify.org",
    "https://ipv6.icanhazip.com",
    NULL
};

/**
 * @brief libcurl write callback function.
 *
 * This function is invoked by libcurl to store received HTTP response data
 * into a dynamically allocated buffer in a response_data structure.
 *
 * @param contents Pointer to the received data.
 * @param size Size of each data element.
 * @param nmemb Number of elements received.
 * @param userdata Pointer to a response_data structure where the data will be appended.
 * @return The number of bytes processed. Returning 0 will cause libcurl to abort the transfer.
 */
static size_t write_callback(
    char *contents, 
    size_t size, 
    size_t nmemb, 
    void *userdata) {
    size_t realsize = size * nmemb;
    Response_t *response = (Response_t *)userdata;

    char *ptr = realloc(response->data, response->size + realsize + 1);
    if (!ptr) {
        log_message(LOG_CRIT, "Not enough memory (realloc returned NULL)");
        return 0;
    }

    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = 0;
    return realsize;
}

/**
 * @brief Logs a message to syslog and optionally to stderr.
 *
 * Messages with priority LOG_WARNING or higher are also printed to stderr.
 *
 * @param priority Syslog priority level (e.g., LOG_INFO, LOG_WARNING, LOG_ERR).
 * @param message Null-terminated string containing the message to log.
 */
static void log_message(
    int priority, 
    const char *message) {
    syslog(priority, "%s", message);
    if (priority <= LOG_WARNING) {
        fprintf(stderr, "DDNS Updater: %s\n", message);
    }
}

/**
 * @brief Validates an IPv4 address string.
 *
 * Uses inet_pton() to verify the format of the IPv4 address.
 *
 * @param ip Null-terminated string containing the IPv4 address.
 * @return 1 if the address is valid, 0 otherwise.
 */
static int is_valid_ipv4(const char *ip) {
    struct in_addr ipv4_addr;

    if (inet_pton(AF_INET, ip, &ipv4_addr) == 1)
    {
        return 1;
    }
    return 0;
}

/**
 * @brief Validates an IPv6 address string.
 *
 * Uses inet_pton() to verify the format of the IPv6 address.
 *
 * @param ip Null-terminated string containing the IPv6 address.
 * @return 1 if the address is valid, 0 otherwise.
 */
static int is_valid_ipv6(const char *ip) {
    struct in6_addr ipv6_addr;

    if (inet_pton(AF_INET6, ip, &ipv6_addr) == 1)
    {
        return 1;
    }
    return 0;
}

/**
 * @brief Fetches the current public IP address.
 *
 * Iterates through a list of IP service URLs to retrieve the public IP, validates it,
 * and stores it in the provided buffer.
 *
 * @param ip_buffer Buffer to store the fetched IP address.
 * @param buffer_size Size of the buffer in bytes.
 * @param ip_services Null-terminated array of URLs to query for the IP.
 * @param ip_type Type of IP to fetch: IPV4_TYPE or IPV6_TYPE.
 * @return 0 on success, -1 on failure.
 */
static int get_current_ip(
    char *ip_buffer, 
    size_t buffer_size, 
    const char* const ip_services[], 
    int ip_type) {
        
    CURL *curl = NULL;
    CURLcode res;
    Response_t response = { .data = NULL, .size = 0 };
    int ret_val = -1;
    size_t i;

    curl = curl_easy_init();
    if (!curl) {
        log_message(LOG_ERR, "Failed to initialize curl");
        return -1;
    }

    for (i = 0; ip_services[i] != NULL; i++) {
        if (response.data) {
            free(response.data);
            response.data = NULL;
            response.size = 0;
        }

        curl_easy_setopt(curl, CURLOPT_URL, ip_services[i]);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "DDNS-Updater/1.0");

        res = curl_easy_perform(curl);

        if (res == CURLE_OK && response.data) {
            char *newline = strchr(response.data, '\n');
            if (newline) *newline = '\0';

            int (*validator)(const char*) = (ip_type == IPV4_TYPE) ? is_valid_ipv4 : is_valid_ipv6;

            if (validator(response.data)) {
                strncpy(ip_buffer, response.data, buffer_size - 1);
                ip_buffer[buffer_size - 1] = '\0';

                char log_msg[BFF];
                snprintf(log_msg, sizeof(log_msg), "Fetched IP (%s) %s", (ip_type == IPV4_TYPE) ? "v4" : "v6", ip_buffer);
                log_message(LOG_INFO, log_msg);
                ret_val = 0;
                goto cleanup;
            }
        }

        char log_msg[BFF];
        snprintf(log_msg, sizeof(log_msg), "IP service %s failed.", ip_services[i]);
        log_message(LOG_WARNING, log_msg);
    }

cleanup:
    if (response.data) free(response.data);
    if (curl) curl_easy_cleanup(curl);
    return ret_val;
}

/**
 * @brief Extracts the value associated with a key from a JSON string.
 *
 * Uses regular expressions to locate the key and returns a dynamically
 * allocated string containing its value.
 *
 * @param json Null-terminated JSON string.
 * @param key Key to search for in the JSON.
 * @return Pointer to a dynamically allocated string containing the value,
 *         or NULL if the key was not found. Caller must free the memory.
 */
static char* extract_json_value(
    const char *json, 
    const char *key) {

    char search_pattern[H_BFF];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\":\"([^\"]+)\"", key);

    regex_t regex;
    regmatch_t matches[2];
    char *result = NULL;

    if (regcomp(&regex, search_pattern, REG_EXTENDED) != 0) {
        log_message(LOG_ERR, "Could not compile JSON regex.");
        return NULL;
    }

    if (regexec(&regex, json, 2, matches, 0) == 0) {
        size_t len = matches[1].rm_eo - matches[1].rm_so;
        result = malloc(len + 1);
        if (result) {
            strncpy(result, json + matches[1].rm_so, len);
            result[len] = '\0';
        }
    }

    regfree(&regex);
    return result;
}

/**
 * @brief Prepares HTTP headers for Cloudflare API requests.
 *
 * Adds authentication headers (X-Auth-Key or Bearer token) and optionally
 * sets Content-Type to application/json.
 *
 * @param include_json INCLUDE_JSON to add Content-Type header, NO_JSON otherwise.
 * @return Pointer to a curl_slist containing the headers. Must be freed with curl_slist_free_all().
 */
static struct curl_slist* prepare_headers(int include_json) {
    struct curl_slist *headers = NULL;
    char auth_header[BFF];
    char email_header[BFF];

    snprintf(email_header, sizeof(email_header), "X-Auth-Email: %s", AUTH_EMAIL);

    if (strcmp(AUTH_METHOD, "global") == 0) {
        snprintf(auth_header, sizeof(auth_header), "X-Auth-Key: %s", AUTH_KEY);
    } else {
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", AUTH_KEY);
    }

    headers = curl_slist_append(headers, email_header);
    headers = curl_slist_append(headers, auth_header);

    if (include_json) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
    }

    return headers;
}

/**
 * @brief Retrieves a DNS record from Cloudflare.
 *
 * Fetches the current DNS record's content and ID for a given record name and type.
 *
 * @param old_ip Buffer to store the current IP stored in the DNS record.
 * @param record_id Buffer to store the Cloudflare record ID.
 * @param record_name DNS record name (e.g., "example.com").
 * @param record_type DNS record type ("A" for IPv4, "AAAA" for IPv6).
 * @return EXIT_SUCCESS if the record was retrieved successfully, EXIT_FAILURE otherwise.
 */
static int get_dns_record(
    char *old_ip, 
    char *record_id, 
    const char *record_name, 
    const char *record_type) {
    
    CURL *curl = NULL;
    Response_t response = { .data = NULL, .size = 0 };
    struct curl_slist *headers = NULL;
    char url[D_BFF];
    int ret_val = EXIT_FAILURE;

    curl = curl_easy_init();
    if (!curl) {
        log_message(LOG_ERR, "Failed to initialize curl for record check.");
        return EXIT_FAILURE;
    }

    headers = prepare_headers(NO_JSON);
    if (!headers) {
        goto cleanup;
    }

    snprintf(url, sizeof(url),
             CLOUDFLARE_API_DNS_QUERY,
             ZONE_IDENTIFIER, record_type, record_name);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    char log_msg[BFF];
    snprintf(log_msg, sizeof(log_msg), "Checking DNS record for %s (%s)", record_name, record_type);
    log_message(LOG_INFO, log_msg);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK && response.data) {
        if (strstr(response.data, "\"count\":0")) {
            snprintf(log_msg, sizeof(log_msg), "Record for %s does not exist. Please create one.", record_name);
            log_message(LOG_ERR, log_msg);
            ret_val = EXIT_FAILURE;
        } else {
            char *old_ip_str = extract_json_value(response.data, "content");
            char *record_id_str = extract_json_value(response.data, "id");

            if (old_ip_str && record_id_str) {
                strncpy(old_ip, old_ip_str, (strcmp(record_type, "A") == 0) ? MAX_IP_SIZE_V4 - 1 : MAX_IP_SIZE_V6 - 1);
                old_ip[(strcmp(record_type, "A") == 0) ? MAX_IP_SIZE_V4 - 1 : MAX_IP_SIZE_V6 - 1] = '\0';
                strncpy(record_id, record_id_str, MAX_RECORD_ID_SIZE - 1);
                record_id[MAX_RECORD_ID_SIZE - 1] = '\0';
                ret_val = EXIT_SUCCESS;
            }

            if (old_ip_str) free(old_ip_str);
            if (record_id_str) free(record_id_str);
        }
    } else {
        log_message(LOG_ERR, "Failed to perform DNS record check via curl.");
    }

cleanup:
    if (response.data) free(response.data);
    if (headers) curl_slist_free_all(headers);
    if (curl) curl_easy_cleanup(curl);
    return ret_val;
}

/**
 * @brief Updates a DNS record at Cloudflare.
 *
 * Sends a PATCH request to update the DNS record to the specified IP.
 *
 * @param current_ip New IP address to set in the DNS record.
 * @param record_id Cloudflare record ID to update.
 * @param record_name DNS record name.
 * @param record_type DNS record type ("A" or "AAAA").
 * @return EXIT_SUCCESS if the update succeeded, EXIT_FAILURE otherwise.
 */
static int update_dns_record(
    const char *current_ip, 
    const char *record_id, 
    const char *record_name, 
    const char *record_type) {
    
    CURL *curl = NULL;
    Response_t response = { .data = NULL, .size = 0 };
    struct curl_slist *headers = NULL;
    char url[D_BFF];
    char json_data[D_BFF];
    int ret_val = EXIT_FAILURE;

    curl = curl_easy_init();
    if (!curl) {
        log_message(LOG_ERR, "Failed to initialize curl for record update.");
        return EXIT_FAILURE;
    }

    headers = prepare_headers(INCLUDE_JSON);
    if (!headers) {
        goto cleanup;
    }

    snprintf(url, sizeof(url),
        CLOUDFLARE_API_DNS_RECORD,
        ZONE_IDENTIFIER, record_id);

    snprintf(json_data, sizeof(json_data),
        "{\"type\":\"%s\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":%d,\"proxied\":%s}",
        record_type, record_name, current_ip, TTL, PROXY);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK && response.data) {
        if (strstr(response.data, "\"success\":false")) {
            log_message(LOG_ERR, "DDNS update failed.");
            log_message(LOG_ERR, response.data);
            ret_val = EXIT_FAILURE;
        } else {
            char log_msg[BFF];
            snprintf(log_msg, sizeof(log_msg), "DDNS updated successfully for %s to IP %s.", record_name, current_ip);
            log_message(LOG_INFO, log_msg);
            ret_val = EXIT_SUCCESS;
        }
    } else {
        log_message(LOG_ERR, "Failed to perform DNS record update via curl.");
    }

cleanup:
    if (response.data) free(response.data);
    if (headers) curl_slist_free_all(headers);
    if (curl) curl_easy_cleanup(curl);
    return ret_val;
}

/**
 * @brief Updates a DNS record if the public IP has changed.
 *
 * Unified function for IPv4 and IPv6. Retrieves the current public IP,
 * compares it to the stored DNS record, and updates the record if necessary.
 *
 * @param record_name DNS record name.
 * @param record_type DNS record type ("A" or "AAAA").
 * @param current_ip Buffer to store the current public IP.
 * @param ip_size Size of the current_ip buffer.
 * @param old_ip Buffer to store the previous IP from the DNS record.
 * @param record_id Buffer to store the Cloudflare record ID.
 * @param ip_services Array of IP service URLs to fetch the current IP.
 * @param ip_version IP version: IPV4_TYPE or IPV6_TYPE.
 * @return EXIT_SUCCESS if the record is up-to-date or was updated successfully,
 *         EXIT_FAILURE otherwise.
 */
static int update_ip_record(
    const char *record_name,
    const char *record_type,
    char *current_ip,
    size_t ip_size,
    char *old_ip,
    char *record_id,
    const char *const ip_services[],
    int ip_version) {

    log_message(LOG_INFO, ip_version == IPV4_TYPE ? "Starting IPv4 update process." : "Starting IPv6 update process.");

    if (get_current_ip(current_ip, ip_size, ip_services, ip_version) != EXIT_SUCCESS)
    {
        log_message(ip_version == IPV4_TYPE ? LOG_ERR : LOG_WARNING,
                    ip_version == IPV4_TYPE ? "Failed to get current IPv4 address." : "Failed to get current IPv6 address.");
        return EXIT_FAILURE;
    }

    if (get_dns_record(old_ip, record_id, record_name, record_type) != EXIT_SUCCESS)
    {
        return EXIT_FAILURE;
    }

    if (strcmp(current_ip, old_ip) != 0)
    {
        if (update_dns_record(current_ip, record_id, record_name, record_type) != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        char log_msg[BFF];
        snprintf(log_msg, sizeof(log_msg), "%s (%s) for %s has not changed. No update needed.",
                 ip_version == IPV4_TYPE ? "IPv4" : "IPv6", current_ip, record_name);
        log_message(LOG_INFO, log_msg);
    }

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    int status = EXIT_SUCCESS;

    // Initialize syslog and curl once
    openlog(LOG_ID, LOG_PID | LOG_CONS, LOG_USER);
    curl_global_init(CURL_GLOBAL_DEFAULT);

#if ENABLE_IPV4
{
    char current_ip_v4[MAX_IP_SIZE_V4];
    char old_ip_v4[MAX_IP_SIZE_V4];
    char record_id_v4[MAX_RECORD_ID_SIZE];

    if (update_ip_record(RECORD_NAME_IPV4, IPV4_RECORD, current_ip_v4, sizeof(current_ip_v4),
                         old_ip_v4, record_id_v4, ip_services_v4, IPV4_TYPE) != EXIT_SUCCESS) {
        status = EXIT_FAILURE;
    }
}
#endif

#if ENABLE_IPV6
{
    char current_ip_v6[MAX_IP_SIZE_V6];
    char old_ip_v6[MAX_IP_SIZE_V6];
    char record_id_v6[MAX_RECORD_ID_SIZE];

    if (update_ip_record(RECORD_NAME_IPV6, IPV6_RECORD, current_ip_v6, sizeof(current_ip_v6),
                         old_ip_v6, record_id_v6, ip_services_v6, IPV6_TYPE) != EXIT_SUCCESS) {
        status = EXIT_FAILURE;
    }
}
#endif

    curl_global_cleanup();
    closelog();

    return status;
}

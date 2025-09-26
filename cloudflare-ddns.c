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

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <regex.h>
#include <syslog.h>
#include <unistd.h>
#include "cloudflare-ddns.h"

/* 
    Costant 
*/
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

#define JSON_QUETY_FORMAT "{\"type\":\"%s\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":%s,\"proxied\":%s}"

#define LOG_ID "CF-DDNS-U"
#define USER_AGENT "CF-DDNS-U"

#define MAX_TTL 86400 /* One day in secornd */
#define AUTO_TTL 1
#define AUTO_TTL_KEYWORD "1"  /* Cloudflare uses 1 for 'automatic' TTL */
#define MIN_TTL_ENTERPRISE 30
#define MIN_TTL 60

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
static size_t write_callback(
    char *contents, 
    size_t size, 
    size_t nmemb, 
    void *userdata) {
    size_t realsize = size * nmemb;
    Response_t *response = (Response_t *) userdata;

    char *ptr = realloc(response->data, response->size + realsize + 1);
    if (!ptr) {
        log_message(LOG_CRIT, "Not enough memory (realloc returned NULL)");
        free(response->data);  
        response->data = NULL;
        response->size = 0;
        return 0;
    }

    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = 0;
    return realsize;
}

/**
 * @brief Logs a message via syslog and optionally stderr.
 *
 * Messages with priority LOG_WARNING or higher are mirrored to stderr.
 *
 * @param priority Syslog priority (LOG_INFO, LOG_WARNING, LOG_ERR, etc.).
 * @param message Null-terminated string to log.
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
 * @brief Validates an IPv6 address string.
 *
 * Uses inet_pton() to check format.
 *
 * @param ip IPv6 string.
 * @return 1 if valid, 0 otherwise.
 */
static int is_valid_ipv4(const char *ip) {
    struct in_addr ipv4_addr;

    if (inet_pton(AF_INET, ip, &ipv4_addr)) {
        return 1;
    }
    return 0;
}

/**
 * @brief Validates an IPv6 address string.
 *
 * Uses inet_pton() to check format.
 *
 * @param ip IPv6 string.
 * @return 1 if valid, 0 otherwise.
 */
static int is_valid_ipv6(const char *ip) {
    struct in6_addr ipv6_addr;

    if (inet_pton(AF_INET6, ip, &ipv6_addr)) {
        return 1;
    }
    return 0;
}

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
int get_current_ip(
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
        curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);

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
char* extract_json_value(const char *json, const char *key) {
    if (!json || !key) exit(EXIT_FAILURE);

    char *result = NULL;
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        log_message(LOG_ERR, "Failed to parse JSON response with cJSON.");
        return NULL;
    }

    cJSON *result_array = cJSON_GetObjectItemCaseSensitive(root, "result");
    if (cJSON_IsArray(result_array)) {
        cJSON *first = cJSON_GetArrayItem(result_array, 0);
        if (cJSON_IsObject(first)) {
            const cJSON *value = cJSON_GetObjectItemCaseSensitive(first, key);
            if (cJSON_IsString(value) && value->valuestring) {
                result = strdup(value->valuestring);
            }
        }
    }

    cJSON_Delete(root);
    return result;
}

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
static struct curl_slist* prepare_headers(int include_json, const Config_t *config) {
    struct curl_slist *headers = NULL;
    char auth_header[BFF];
    char email_header[BFF];

    snprintf(email_header, sizeof(email_header), "X-Auth-Email: %s", config->auth_email);

    if (strcmp(config->auth_method, "global") == 0) {
        snprintf(auth_header, sizeof(auth_header), "X-Auth-Key: %s", config->auth_key);
    } else {
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", config->auth_key);
    }

    headers = curl_slist_append(headers, email_header);
    headers = curl_slist_append(headers, auth_header);

    if (include_json) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
    }

    return headers;
}

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
    const Config_t *config) {
    
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

    headers = prepare_headers(NO_JSON,config);
    if (!headers) {
        goto cleanup;
    }

    snprintf(url, sizeof(url),
             CLOUDFLARE_API_DNS_QUERY,
             config->zone_id, record_type, record_name);

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

/* to document */
static int format_ttl(int ttl, const char *proxy, char *out, size_t out_size) {
    if (!out || out_size == 0) return 0;
    /* If proxied is "true" or TTL is AUTO_TTL use Cloudflare's numeric '1' */
    if ((proxy && strcmp(proxy, "true") == 0) || ttl == AUTO_TTL) {
        /* '1' is Cloudflare's auto TTL indicator (numeric) */
        if (snprintf(out, out_size, "%s", AUTO_TTL_KEYWORD) < 0) return 0;
    } else {
        if (snprintf(out, out_size, "%d", ttl) < 0) return 0;
    }
    return 1;
}

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
    const Config_t *config) {
    
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

    headers = prepare_headers(INCLUDE_JSON, config);
    if (!headers) {
        goto cleanup;
    }

    snprintf(url, sizeof(url),
        CLOUDFLARE_API_DNS_RECORD,
        config->zone_id, record_id);

    char ttl_buf[16];

    if (!format_ttl(config->ttl, config->proxy, ttl_buf, sizeof(ttl_buf))) {
        log_message(LOG_ERR, "Failed to format TTL string.");
        goto cleanup;
    }

    snprintf(json_data, sizeof(json_data),
            JSON_QUETY_FORMAT,
            record_type, record_name, current_ip, ttl_buf, config->proxy);


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
 * @brief Retrieves an integer value from an environment variable.
 *
 * Reads the value of an environment variable, converts it to an integer, 
 * and stores it in the provided output pointer.
 *
 * @param name Name of the environment variable.
 * @param out Pointer to store the converted integer value.
 * @return 1 if the variable exists and conversion succeeds, 0 otherwise.
 */
static int getenv_int(const char *name, int *out) {
    char *val = getenv(name);
    if (!val) return 0;  

    *out = atoi(val);
    return 1;
}

/**
 * @brief Validates whether an enable/disable flag is valid.
 *
 * Checks if the given flag is either 0 (disabled) or 1 (enabled).
 *
 * @param enable_ip Integer flag representing enable/disable.
 * @return 1 if valid, 0 otherwise.
 */
static int verify_1_0(int to_verify) {
    if (to_verify == 1 || to_verify == 0) {
        return 1;
    }

    return 0;
}

/**
 * @brief Validates a TTL (Time-To-Live) value.
 *
 * Accepts a value of 1 (representing "auto") or checks if the TTL 
 * falls within the predefined range [MIN_TTL, MAX_TTL].
 *
 * @param ttl TTL value to validate.
 * @return 1 if the TTL is valid, 0 otherwise.
 */
static int verify_ttl(int ttl, int is_enteprise) {
    if (is_enteprise)
        return ttl == 1 || (ttl >= MIN_TTL_ENTERPRISE && ttl <= MAX_TTL);
    else
        return ttl == 1 || (ttl >= MIN_TTL && ttl <= MAX_TTL);
}

/**
 * @brief Verifies the validity of a configuration structure.
 *
 * Ensures that all required fields in the Config_t structure are set, 
 * and that both TTL and enable flags (IPv4, IPv6) are valid.
 *
 * @param config Pointer to the Config_t structure to verify.
 * @return EXIT_SUCCESS if configuration is valid, EXIT_FAILURE otherwise.
 */
static int verify_Config_t(Config_t *config) {
    if (
        !config->auth_email                || 
        !config->auth_method               || 
        !config->auth_key                  || 
        !config->zone_id                   || 
        !config->record_name_ipv4          ||                 
        !config->record_name_ipv6          ||                   
        !config->proxy                     ||
        !verify_1_0(config->is_enterprise) ||
        !verify_1_0(config->enable_ipv4)   ||
        !verify_1_0(config->enable_ipv6)   ||
        !verify_ttl(config->ttl, config->is_enterprise)) {
        log_message(LOG_ERR, "Missing required environment variables! Check your cloudflare-ddns.sh");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * @brief Loads configuration from environment variables.
 *
 * Reads required settings from the environment. Exits program if
 * critical values are missing.
 *
 * @param cfg Pointer to Config_t to populate.
 * @return 0 on success, nonzero on error.
 */
int load_config(Config_t *config) {
    config->auth_email       = getenv("CF_AUTH_EMAIL");
    config->auth_method      = getenv("CF_AUTH_METHOD");
    config->auth_key         = getenv("CF_AUTH_KEY");
    config->zone_id          = getenv("CF_ZONE_ID");
    config->record_name_ipv4 = getenv("CF_RECORD_NAME_IPV4");
    config->record_name_ipv6 = getenv("CF_RECORD_NAME_IPV6");
    config->proxy            = getenv("CF_PROXY");

    if (!getenv_int("CF_TTL", &config->ttl)                 ||
        !getenv_int("CF_ENABLE_IPV4", &config->enable_ipv4) ||
        !getenv_int("CF_ENABLE_IPV6", &config->enable_ipv6) ||
        !getenv_int("CF_IS_ENTERPRISE", &config->is_enterprise)) {
        log_message(LOG_ERR, "Numeric environment variables missing!");
        return EXIT_FAILURE;
    }

    return verify_Config_t(config);
}

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
    Config_t *config) {

    log_message(LOG_INFO, ip_version == IPV4_TYPE ? "Starting IPv4 update process." : "Starting IPv6 update process.");

    if (get_current_ip(current_ip, ip_size, ip_services, ip_version) != EXIT_SUCCESS)
    {
        log_message(ip_version == IPV4_TYPE ? LOG_ERR : LOG_WARNING,
                    ip_version == IPV4_TYPE ? "Failed to get current IPv4 address." : "Failed to get current IPv6 address.");
        return EXIT_FAILURE;
    }

    if (get_dns_record(old_ip, record_id, record_name, record_type, config) != EXIT_SUCCESS)
    {
        return EXIT_FAILURE;
    }

    if (strcmp(current_ip, old_ip) != 0)
    {
        if (update_dns_record(current_ip, record_id, record_name, record_type, config) != EXIT_SUCCESS)
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

    Config_t *config = malloc(sizeof(Config_t));

    
    if (load_config(config) == EXIT_FAILURE)  {
        status = EXIT_FAILURE;
        goto cleanup;
    }

    if (config->enable_ipv4)
    {
        char current_ip_v4[MAX_IP_SIZE_V4];
        char old_ip_v4[MAX_IP_SIZE_V4];
        char record_id_v4[MAX_RECORD_ID_SIZE];

        if (update_ip_record(config->record_name_ipv4, IPV4_RECORD, current_ip_v4, sizeof(current_ip_v4),
                             old_ip_v4, record_id_v4, ip_services_v4, IPV4_TYPE, config) != EXIT_SUCCESS)
        {
            status = EXIT_FAILURE;
            goto cleanup;
        }
    }

    if (config->enable_ipv6)
    {
        char current_ip_v6[MAX_IP_SIZE_V6];
        char old_ip_v6[MAX_IP_SIZE_V6];
        char record_id_v6[MAX_RECORD_ID_SIZE];

        if (update_ip_record(config->record_name_ipv6, IPV6_RECORD, current_ip_v6, sizeof(current_ip_v6),
                             old_ip_v6, record_id_v6, ip_services_v6, IPV6_TYPE, config) != EXIT_SUCCESS)
        {
            status = EXIT_FAILURE;
            goto cleanup;
        }
    }
    
cleanup:
    if(config) free(config);
    curl_global_cleanup();
    closelog();

    return status;
}

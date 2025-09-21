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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <regex.h>
#include <syslog.h>
#include <unistd.h>
#include "config.h"

// Constants
#define MAX_IP_SIZE 16
#define MAX_RECORD_ID_SIZE 64
#define IPV4_REGEX "^(0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\\.){3}0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))$"
#define HALF_BUFF 128
#define BUFF 256
#define DOUBLE_BUFF 512

// IP services to try
static const char* const ipv4_services[] = {
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    NULL
};

// Structure to hold response data
struct response_data {
    char *data;
    size_t size;
};

// Function Prototypes 
static size_t write_callback(char *contents, size_t size, size_t nmemb, void *userdata);
static void log_message(int priority, const char *message);
static int is_valid_ipv4(const char *ip);
static int get_current_ip(char *ip_buffer, size_t buffer_size);
static char* extract_json_value(const char *json, const char *key);
static int get_dns_record(const char *current_ip, char *old_ip, char *record_id);
static int update_dns_record(const char *current_ip, const char *record_id);
static struct curl_slist* prepare_headers();

// Function Implementations 

// Callback function for libcurl to write response data
static size_t write_callback(char *contents, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    struct response_data *response = (struct response_data *)userdata;

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

// Log message to syslog and console
static void log_message(int priority, const char *message) {
    syslog(priority, "%s", message);
    if (priority <= LOG_WARNING) {
        fprintf(stderr, "DDNS Updater: %s\n", message);
    }
}

// Validate IPv4 address using regex
static int is_valid_ipv4(const char *ip) {
    regex_t regex;
    int result;

    if (regcomp(&regex, IPV4_REGEX, REG_EXTENDED) != 0) {
        log_message(LOG_ERR, "Could not compile regex.");
        return 0;
    }

    result = regexec(&regex, ip, 0, NULL, 0);
    regfree(&regex);

    return result == 0;
}

// Fetch current public IP address
static int get_current_ip(char *ip_buffer, size_t buffer_size) {
    CURL *curl = NULL;
    CURLcode res;
    struct response_data response = { .data = NULL, .size = 0 };
    int ret_val = -1;
    size_t i;

    curl = curl_easy_init();
    if (!curl) {
        log_message(LOG_ERR, "Failed to initialize curl");
        return -1;
    }

    for (i = 0; ipv4_services[i] != NULL; i++) {
        if (response.data) {
            free(response.data);
            response.data = NULL;
            response.size = 0;
        }

        curl_easy_setopt(curl, CURLOPT_URL, ipv4_services[i]);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "DDNS-Updater/1.0");

        res = curl_easy_perform(curl);

        if (res == CURLE_OK && response.data) {
            char *newline = strchr(response.data, '\n');
            if (newline) *newline = '\0';

            if (is_valid_ipv4(response.data)) {
                strncpy(ip_buffer, response.data, buffer_size - 1);
                ip_buffer[buffer_size - 1] = '\0';

                char log_msg[BUFF];
                snprintf(log_msg, sizeof(log_msg), "Fetched IP %s", ip_buffer);
                log_message(LOG_INFO, log_msg);
                ret_val = 0;
                goto cleanup;
            }
        }

        char log_msg[BUFF];
        snprintf(log_msg, sizeof(log_msg), "IP service %s failed.", ipv4_services[i]);
        log_message(LOG_WARNING, log_msg);
    }

cleanup:
    if (response.data) free(response.data);
    if (curl) curl_easy_cleanup(curl);
    return ret_val;
}

// Extract content from JSON response
static char* extract_json_value(const char *json, const char *key) {
    char search_pattern[HALF_BUFF];
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

// Prepare common Cloudflare API headers
static struct curl_slist* prepare_headers() {
    struct curl_slist *headers = NULL;
    char auth_header[BUFF];
    char email_header[BUFF];

    snprintf(email_header, sizeof(email_header), "X-Auth-Email: %s", AUTH_EMAIL);

    if (strcmp(AUTH_METHOD, "global") == 0) {
        snprintf(auth_header, sizeof(auth_header), "X-Auth-Key: %s", AUTH_KEY);
    } else {
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", AUTH_KEY);
    }

    headers = curl_slist_append(headers, email_header);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    return headers;
}


// Get DNS record information from Cloudflare
static int get_dns_record(const char *current_ip, char *old_ip, char *record_id) {
    CURL *curl = NULL;
    struct response_data response = { .data = NULL, .size = 0 };
    struct curl_slist *headers = NULL;
    char url[DOUBLE_BUFF];
    int ret_val = EXIT_FAILURE;

    curl = curl_easy_init();
    if (!curl) {
        log_message(LOG_ERR, "Failed to initialize curl for record check.");
        return EXIT_FAILURE;
    }

    headers = prepare_headers();
    if (!headers) {
        goto cleanup;
    }

    snprintf(url, sizeof(url),
        "https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=A&name=%s",
        ZONE_IDENTIFIER, RECORD_NAME);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    log_message(LOG_INFO, "Check Initiated");
    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK && response.data) {
        if (strstr(response.data, "\"count\":0")) {
            char log_msg[BUFF];
            snprintf(log_msg, sizeof(log_msg),
                "Record for %s does not exist. Please create one.", RECORD_NAME);
            log_message(LOG_ERR, log_msg);
            ret_val = EXIT_FAILURE;
        } else {
            char *old_ip_str = extract_json_value(response.data, "content");
            char *record_id_str = extract_json_value(response.data, "id");

            if (old_ip_str && record_id_str) {
                strncpy(old_ip, old_ip_str, MAX_IP_SIZE - 1);
                old_ip[MAX_IP_SIZE - 1] = '\0';
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

// Update DNS record at Cloudflare
static int update_dns_record(const char *current_ip, const char *record_id) {
    CURL *curl = NULL;
    struct response_data response = { .data = NULL, .size = 0 };
    struct curl_slist *headers = NULL;
    char url[DOUBLE_BUFF];
    char json_data[DOUBLE_BUFF];
    int ret_val = EXIT_FAILURE;

    curl = curl_easy_init();
    if (!curl) {
        log_message(LOG_ERR, "Failed to initialize curl for record update.");
        return EXIT_FAILURE;
    }

    headers = prepare_headers();
    if (!headers) {
        goto cleanup;
    }

    snprintf(url, sizeof(url),
        "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s",
        ZONE_IDENTIFIER, record_id);

    snprintf(json_data, sizeof(json_data),
        "{\"type\":\"A\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":%d,\"proxied\":%s}",
        RECORD_NAME, current_ip, TTL, PROXY);

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
            char log_msg[BUFF];
            snprintf(log_msg, sizeof(log_msg), "DDNS updated successfully for %s to IP %s.", RECORD_NAME, current_ip);
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

int main(int argc, char *argv[]) {
    char current_ip[MAX_IP_SIZE];
    char old_ip[MAX_IP_SIZE];
    char record_id[MAX_RECORD_ID_SIZE];
    int status = EXIT_SUCCESS;

    // Initialize syslog and curl once
    openlog("DDNS Updater", LOG_PID | LOG_CONS, LOG_USER);
    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (get_current_ip(current_ip, sizeof(current_ip)) != 0) {
        log_message(LOG_ERR, "Failed to get current IP address.");
        status = EXIT_FAILURE;
        goto cleanup;
    }

    if (get_dns_record(current_ip, old_ip, record_id) != EXIT_SUCCESS) {
        status = EXIT_FAILURE;
        goto cleanup;
    }

    if (strcmp(current_ip, old_ip) == 0) {
        char log_msg[BUFF];
        snprintf(log_msg, sizeof(log_msg), "IP (%s) for %s has not changed. No update needed.", current_ip, RECORD_NAME);
        log_message(LOG_INFO, log_msg);
        goto cleanup;
    }

    if (update_dns_record(current_ip, record_id) != EXIT_SUCCESS) {
        status = EXIT_FAILURE;
        goto cleanup;
    }

cleanup:
    curl_global_cleanup();
    closelog();
    return status;
}


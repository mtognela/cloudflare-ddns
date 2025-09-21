/*
    Cloudflare Dynamic DNS Updater writter in C
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
#define MAX_RESPONSE_SIZE 4096
#define MAX_IP_SIZE 16
#define MAX_RECORD_ID_SIZE 64
#define IPV4_REGEX "^(0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\\.){3}0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))$"

// IP services to try that if curl respond with your ip adress 
static const char* ip_services[] = {
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com", 
    "https://ipinfo.io/ip",
    NULL
};

// Structure to hold response data
struct response_data {
    char *data;
    size_t size;
};

// Callback function for libcurl to write response data
static size_t write_callback(void *contents, size_t size, size_t nmemb, struct response_data *response) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(response->data, response->size + realsize + 1);
    
    if (!ptr) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = 0;
    
    return realsize;
}

// Log message to syslog
void log_message(int priority, const char *message) {
    openlog("DDNS Updater", LOG_PID | LOG_CONS, LOG_USER);
    syslog(priority, "%s", message);
    closelog();
    
    if (priority <= LOG_WARNING) {
        printf("DDNS Updater: %s\n", message);
    }
}

// Validate IPv4 address using regex
int is_valid_ipv4(const char *ip) {
    regex_t regex;
    int result;
    
    if (regcomp(&regex, IPV4_REGEX, REG_EXTENDED) != 0) {
        return 0;
    }
    
    result = regexec(&regex, ip, 0, NULL, 0);
    regfree(&regex);
    
    return result == 0;
}

// Fetch current public IP address
int get_current_ip(char *ip_buffer, size_t buffer_size) {
    CURL *curl;
    CURLcode res;
    struct response_data response = {0};
    int i;
    
    curl = curl_easy_init();
    if (!curl) {
        log_message(LOG_ERR, "Failed to initialize curl");
        return -1;
    }
    
    for (i = 0; ip_services[i] != NULL; i++) {
        // Reset response data
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
            // Remove trailing newline if present
            char *newline = strchr(response.data, '\n');
            if (newline) *newline = '\0';
            
            if (is_valid_ipv4(response.data)) {
                strncpy(ip_buffer, response.data, buffer_size - 1);
                ip_buffer[buffer_size - 1] = '\0';
                
                char log_msg[256];
                snprintf(log_msg, sizeof(log_msg), "Fetched IP %s", ip_buffer);
                log_message(LOG_INFO, log_msg);
                
                free(response.data);
                curl_easy_cleanup(curl);
                return 0;
            }
        }
        
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "IP service %s failed.", ip_services[i]);
        log_message(LOG_WARNING, log_msg);
    }
    
    if (response.data) free(response.data);
    curl_easy_cleanup(curl);
    return -1;
}

// Extract content from JSON response using simple string parsing
char* extract_json_value(const char *json, const char *key) {
    char search_pattern[128];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\":\"", key);
    
    char *start = strstr(json, search_pattern);
    if (!start) return NULL;
    
    start += strlen(search_pattern);
    char *end = strchr(start, '"');
    if (!end) return NULL;
    
    size_t len = end - start;
    char *result = malloc(len + 1);
    if (result) {
        strncpy(result, start, len);
        result[len] = '\0';
    }
    
    return result;
}

// Get DNS record information from Cloudflare
int get_dns_record(const char *current_ip, char *old_ip, char *record_id) {
    CURL *curl;
    CURLcode res;
    struct response_data response = {0};
    struct curl_slist *headers = NULL;
    char url[512];
    char auth_header[256];
    char email_header[256];
    int result = -1;
    
    curl = curl_easy_init();
    if (!curl) return -1;
    
    // Prepare headers
    snprintf(email_header, sizeof(email_header), "X-Auth-Email: %s", AUTH_EMAIL);
    
    if (strcmp(AUTH_METHOD, "global") == 0) {
        snprintf(auth_header, sizeof(auth_header), "X-Auth-Key: %s", AUTH_KEY);
    } else {
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", AUTH_KEY);
    }
    
    headers = curl_slist_append(headers, email_header);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    // Prepare URL
    snprintf(url, sizeof(url), 
        "https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=A&name=%s",
        ZONE_IDENTIFIER, RECORD_NAME);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    log_message(LOG_INFO, "Check Initiated");
    res = curl_easy_perform(curl);
    
    if (res == CURLE_OK && response.data) {
        // Check if record exists
        if (strstr(response.data, "\"count\":0")) {
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), 
                "Record does not exist, perhaps create one first? (%s for %s)", 
                current_ip, RECORD_NAME);
            log_message(LOG_ERR, log_msg);
            result = 1;
        } else {
            // Extract old IP and record ID
            char *old_ip_str = extract_json_value(response.data, "content");
            char *record_id_str = extract_json_value(response.data, "id");
            
            if (old_ip_str && record_id_str) {
                strcpy(old_ip, old_ip_str);
                strcpy(record_id, record_id_str);
                result = 0;
            }
            
            if (old_ip_str) free(old_ip_str);
            if (record_id_str) free(record_id_str);
        }
    }
    
    if (response.data) free(response.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    return result;
}

// Update DNS record at Cloudflare
int update_dns_record(const char *current_ip, const char *record_id) {
    CURL *curl;
    CURLcode res;
    struct response_data response = {0};
    struct curl_slist *headers = NULL;
    char url[512];
    char auth_header[256];
    char email_header[256];
    char json_data[512];
    int result = -1;
    
    curl = curl_easy_init();
    if (!curl) return -1;
    
    // Prepare headers
    snprintf(email_header, sizeof(email_header), "X-Auth-Email: %s", AUTH_EMAIL);
    
    if (strcmp(AUTH_METHOD, "global") == 0) {
        snprintf(auth_header, sizeof(auth_header), "X-Auth-Key: %s", AUTH_KEY);
    } else {
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", AUTH_KEY);
    }
    
    headers = curl_slist_append(headers, email_header);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    // Prepare URL and JSON data
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
    
    res = curl_easy_perform(curl);
    
    if (res == CURLE_OK && response.data) {
        if (strstr(response.data, "\"success\":false")) {
            char log_msg[1024];
            snprintf(log_msg, sizeof(log_msg),
                "%s %s DDNS failed for %s (%s). DUMPING RESULTS:\n%s",
                current_ip, RECORD_NAME, record_id, current_ip, response.data);
            log_message(LOG_ERR, log_msg);
            result = 1;
        } else {
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "%s %s DDNS updated.", current_ip, RECORD_NAME);
            log_message(LOG_INFO, log_msg);
            result = 0;
        }
    }
    
    if (response.data) free(response.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    return result;
}

int main(int argc, char *argv[]) {
    char current_ip[MAX_IP_SIZE];
    char old_ip[MAX_IP_SIZE];
    char record_id[MAX_RECORD_ID_SIZE];
    char notification_msg[512];
    
    // Initialize curl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Get current public IP
    if (get_current_ip(current_ip, sizeof(current_ip)) != 0) {
        log_message(LOG_ERR, "Failed to find a valid IP.");
        curl_global_cleanup();
        return 2;
    }
    
    // Get DNS record information
    int record_result = get_dns_record(current_ip, old_ip, record_id);
    if (record_result == 1) {
        curl_global_cleanup();
        return 1;
    } else if (record_result != 0) {
        log_message(LOG_ERR, "Failed to get DNS record information.");
        curl_global_cleanup();
        return 1;
    }
    
    // Compare IPs
    if (strcmp(current_ip, old_ip) == 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "IP (%s) for %s has not changed.", current_ip, RECORD_NAME);
        log_message(LOG_INFO, log_msg);
        curl_global_cleanup();
        return 0;
    }
    
    // Update DNS record
    int update_result = update_dns_record(current_ip, record_id);
    int return_value = 0; 

    if (update_result != 0) {
        return_value = 1;
    }

    curl_global_cleanup();

    return return_value;
}

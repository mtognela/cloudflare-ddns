#ifndef CLOUDFLARE_DDNS_H
#define CLOUDFLARE_DDNS_H

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

#include <stddef.h> 
#include "config.h" 

/**
 * @Response
 * @brief Stores the response data received from a libcurl HTTP request.
 *
 * This structure holds a dynamically allocated buffer containing the response
 * and its current size.
 */
typedef struct {
    char *data; /**< Pointer to dynamically allocated memory holding the response content */
    size_t size; /**< Current size of the response content in bytes */
} Response_t;

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
static size_t write_callback(char *contents, size_t size, size_t nmemb, void *userdata);

/**
 * @brief Logs a message to syslog and optionally to stderr.
 *
 * Messages with priority LOG_WARNING or higher are also printed to stderr.
 *
 * @param priority Syslog priority level (e.g., LOG_INFO, LOG_WARNING, LOG_ERR).
 * @param message Null-terminated string containing the message to log.
 */
static void log_message(int priority, const char *message);

/**
 * @brief Validates an IPv4 address string.
 *
 * Uses inet_pton() to verify the format of the IPv4 address.
 *
 * @param ip Null-terminated string containing the IPv4 address.
 * @return 1 if the address is valid, 0 otherwise.
 */
static int is_valid_ipv4(const char *ip);

/**
 * @brief Validates an IPv6 address string.
 *
 * Uses inet_pton() to verify the format of the IPv6 address.
 *
 * @param ip Null-terminated string containing the IPv6 address.
 * @return 1 if the address is valid, 0 otherwise.
 */
static int is_valid_ipv6(const char *ip);

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
int get_current_ip(char *ip_buffer, size_t buffer_size, const char* const ip_services[], int ip_type);

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
char* extract_json_value(const char *json, const char *key);

/**
 * @brief Prepares HTTP headers for Cloudflare API requests.
 *
 * Adds authentication headers (X-Auth-Key or Bearer token) and optionally
 * sets Content-Type to application/json.
 *
 * @param include_json INCLUDE_JSON to add Content-Type header, NO_JSON otherwise.
 * @return Pointer to a curl_slist containing the headers. Must be freed with curl_slist_free_all().
 */
static struct curl_slist* prepare_headers(int include_json, const Config_t *config);

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
int get_dns_record(
    char *old_ip, 
    char *record_id, 
    const char *record_name, 
    const char *record_type,
    const Config_t *config);

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
int update_dns_record(
    const char *current_ip, 
    const char *record_id, 
    const char *record_name, 
    const char *record_type,
    const Config_t *config);
    
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
    int ip_version,
    Config_t *config);

#endif
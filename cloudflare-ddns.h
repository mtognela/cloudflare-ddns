#ifndef CLOUDFLARE_DDNS_H
#define CLOUDFLARE_DDNS_H

#include <stddef.h>  

static size_t write_callback(
    char *contents, 
    size_t size, 
    size_t nmemb, 
    void *userdata);

static void log_message(
    int priority, 
    const char *message);

static int is_valid_ipv4(const char *ip);

static int is_valid_ipv6(const char *ip);

static int get_current_ip(
    char *ip_buffer, 
    size_t buffer_size, 
    const char* const ip_services[], 
    int ip_type);

static char* extract_json_value(
    const char *json, 
    const char *key);

static struct curl_slist* prepare_headers_get_record_dns();

static struct curl_slist* prepare_headers_update_dns();

static struct curl_slist* prepare_headers(int include_json);

static int get_dns_record(
    char *old_ip, 
    char *record_id, 
    const char *record_name, 
    const char *record_type);

static int update_dns_record(
    const char *current_ip, 
    const char *record_id, 
    const char *record_name, 
    const char *record_type);

static int update_ip_record(
    const char *record_name,
    const char *record_type,
    char *current_ip,
    size_t ip_size,
    char *old_ip,
    char *record_id,
    const char *const ip_services[],
    int ip_version);

#endif
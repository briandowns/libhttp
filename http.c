#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "http.h"

#define UNUSED(x) (void)x

#ifndef HTTP_BASIC_UATH_USER
#define HTTP_BASIC_UATH_USER "user"
#endif
/**
 * trim_whitespace removes any white space on
 * the given string.
 */
static char*
trim_whitespace(char *str)
{
    while(isspace((unsigned char)*str)) {
        str++;
    }
    if (*str == 0) {
        return str;
    }

    char *end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) {
        end--;
    }
    end[1] = '\0';

    return str;
}

/**
 * slice_str removes a portion of the given string.
 */
static void
slice_str(const char *str, char *buffer, size_t start, size_t end)
{
    size_t j = 0;

    for (size_t i = start; i <= end; ++i) {
        buffer[j++] = str[i];
    }
    buffer[j] = 0;
}

char*
get_header_value(const char *header, char *key)
{
    if (!header || !header[0]) {
        return NULL;
    }
    if (!key || !key[0]) {
        return NULL;
    }

    char *tmp = malloc(strlen(header)+2);
    strcpy(tmp, header);
    size_t header_len = strlen(header);
    char *value = malloc(header_len+1);
    slice_str(header, value, strlen(key)+2, header_len+1);

    return value;
}

void
log_request(const struct _u_request *request, struct _u_response *response, clock_t start)
{
    clock_t diff = clock() - start;
    int msec = diff * 1000;

    s_log(S_LOG_INFO,
        s_log_string("method", request->http_verb), 
        s_log_string("path", request->url_path),
        //s_log_string("host", ipv4),
        s_log_uint32("status", response->status),
        s_log_string("proto", request->http_protocol),
        s_log_int("duration", msec),
        s_log_string("client_addr", inet_ntoa(((struct sockaddr_in*)request->client_address)->sin_addr)),
        s_log_string("user-agent", u_map_get(request->map_header, "User-Agent")));
}

/**
 * callback_default is used to handled calls that don't have
 * a matching route. Returns an expected 404.
 */
int
callback_default(const struct _u_request *request, struct _u_response *response, void *user_data)
{
    ulfius_set_string_body_response(response, HTTP_STATUS_CODE_NOT_FOUND, "page not found");
 
    return U_CALLBACK_CONTINUE;
}

/**
 * callback_health_check handles all health check
 * requests to the thinq service.
 */
int
callback_health_check(const struct _u_request *request, struct _u_response *response, void *user_data)
{
    clock_t start = clock();

    const char *git_hash = (const char *)user_data;
    
    json_t * json_body = json_object();
    json_object_set_new(json_body, "status", json_string("OK")); 
    json_object_set_new(json_body, "git_sha", json_string(git_hash));

    ulfius_set_json_body_response(response, HTTP_STATUS_CODE_OK, json_body);
    json_decref(json_body);

    log_request(request, response, start);

    return U_CALLBACK_CONTINUE;
}

int
callback_auth_token(const struct _u_request *request, struct _u_response *response, void *user_data)
{
    //const char *token = u_map_get(request->map_header, AUTH_HEADER);

    //char *token = u_map_get(request->map_url, AUTH_HEADER);

    return U_CALLBACK_CONTINUE;
}

/**
 * Auth function for basic authentication
 */
int callback_auth_basic_body (const struct _u_request * request, struct _u_response * response, void * user_data) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "basic auth user: %s", request->auth_basic_user);
    y_log_message(Y_LOG_LEVEL_DEBUG, "basic auth password: %s", request->auth_basic_password);
    y_log_message(Y_LOG_LEVEL_DEBUG, "basic auth param: %s", (char *)user_data);
    if (request->auth_basic_user != NULL && request->auth_basic_password != NULL && 
    0 == o_strcmp(request->auth_basic_user, USER) && 0 == o_strcmp(request->auth_basic_password, PASSWORD)) {
    return U_CALLBACK_CONTINUE;
    } else {
    ulfius_set_string_body_response(response, 401, "Error authentication");
    return U_CALLBACK_UNAUTHORIZED;
    }
}

/**
 * Callback function for basic authentication
 */
int callback_auth_basic (const struct _u_request * request, struct _u_response * response, void * user_data) {
    UNUSED(request);
    UNUSED(user_data);

    ulfius_set_string_body_response(response, 200, "Basic auth callback");
    return U_CALLBACK_CONTINUE;
}

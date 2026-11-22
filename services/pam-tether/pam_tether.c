#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define DEFAULT_SOCKET_PATH "/run/tether/auth.sock"
#define DEFAULT_TIMEOUT_SEC 3
#define MAX_BUFFER_SIZE 4096

static void secure_clean(void *p, size_t len)
{
    if (p == NULL || len == 0) return;
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (len--) {
        *v++ = 0;
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    const char *socket_path = DEFAULT_SOCKET_PATH;
    int timeout_sec = DEFAULT_TIMEOUT_SEC;
    int debug = 0;

    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "socket=", 7) == 0) {
            socket_path = argv[i] + 7;
        } else if (strncmp(argv[i], "timeout=", 8) == 0) {
            timeout_sec = atoi(argv[i] + 8);
            if (timeout_sec <= 0) timeout_sec = DEFAULT_TIMEOUT_SEC;
        } else if (strcmp(argv[i], "debug") == 0) {
            debug = 1;
        }
    }

    const char *username = NULL;
    int rc = pam_get_user(pamh, &username, NULL);
    if (rc != PAM_SUCCESS || username == NULL || username[0] == '\0') {
        if (debug) syslog(LOG_AUTHPRIV | LOG_DEBUG, "pam_tether: pam_get_user failed or empty username");
        return PAM_USER_UNKNOWN;
    }

    const char *service = NULL;
    pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    if (service == NULL) service = "unknown";

    if (debug) {
        syslog(LOG_AUTHPRIV | LOG_DEBUG, "pam_tether: authenticating user '%s' for service '%s'", username, service);
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_WARNING, "pam_tether: socket() failed: %m");
        return PAM_AUTHINFO_UNAVAIL;
    }

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_DEBUG, "pam_tether: connect(%s) failed: %m", socket_path);
        close(fd);
        return PAM_AUTHINFO_UNAVAIL;
    }

    char req_json[512];
    int json_len = snprintf(req_json, sizeof(req_json),
        "{\"action\":\"AUTH_REQUEST\",\"user\":\"%s\",\"service\":\"%s\"}",
        username, service);

    if (json_len <= 0 || (size_t)json_len >= sizeof(req_json)) {
        close(fd);
        return PAM_SERVICE_ERR;
    }

    uint32_t len_be = htonl((uint32_t)json_len);
    if (write(fd, &len_be, 4) != 4 || write(fd, req_json, json_len) != json_len) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_WARNING, "pam_tether: write to socket failed: %m");
        secure_clean(req_json, sizeof(req_json));
        close(fd);
        return PAM_AUTHINFO_UNAVAIL;
    }
    secure_clean(req_json, sizeof(req_json));

    uint32_t resp_len_be = 0;
    ssize_t r = read(fd, &resp_len_be, 4);
    if (r != 4) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_DEBUG, "pam_tether: failed reading response length: %m");
        close(fd);
        return PAM_AUTHINFO_UNAVAIL;
    }

    uint32_t resp_len = ntohl(resp_len_be);
    if (resp_len == 0 || resp_len > MAX_BUFFER_SIZE) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_WARNING, "pam_tether: invalid response length %u", resp_len);
        close(fd);
        return PAM_SERVICE_ERR;
    }

    char *resp_buf = malloc(resp_len + 1);
    if (resp_buf == NULL) {
        close(fd);
        return PAM_BUF_ERR;
    }

    size_t total_read = 0;
    while (total_read < resp_len) {
        ssize_t chunk = read(fd, resp_buf + total_read, resp_len - total_read);
        if (chunk <= 0) break;
        total_read += chunk;
    }
    close(fd);

    if (total_read < resp_len) {
        secure_clean(resp_buf, resp_len + 1);
        free(resp_buf);
        return PAM_AUTHINFO_UNAVAIL;
    }

    resp_buf[resp_len] = '\0';

    int auth_result = PAM_AUTH_ERR;
    if (strstr(resp_buf, "\"status\":\"SUCCESS\"") != NULL ||
        strstr(resp_buf, "\"status\": \"SUCCESS\"") != NULL) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_INFO, "pam_tether: authentication successful for user '%s'", username);
        auth_result = PAM_SUCCESS;
    } else {
        if (debug) syslog(LOG_AUTHPRIV | LOG_NOTICE, "pam_tether: authentication denied for user '%s'", username);
        auth_result = PAM_AUTH_ERR;
    }

    secure_clean(resp_buf, resp_len + 1);
    free(resp_buf);
    return auth_result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;
    const char *username = NULL;
    int rc = pam_get_user(pamh, &username, NULL);
    if (rc != PAM_SUCCESS || username == NULL || username[0] == '\0') {
        return PAM_USER_UNKNOWN;
    }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SERVICE_ERR;
}

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

static int json_escape_string(const char *src, char *dst, size_t dst_size)
{
    if (!src || !dst || dst_size == 0) return -1;
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0'; s++) {
        unsigned char c = (unsigned char)src[s];
        if (c == '"' || c == '\\') {
            if (d + 2 >= dst_size) return -1;
            dst[d++] = '\\';
            dst[d++] = (char)c;
        } else if (c == '\b') {
            if (d + 2 >= dst_size) return -1;
            dst[d++] = '\\'; dst[d++] = 'b';
        } else if (c == '\f') {
            if (d + 2 >= dst_size) return -1;
            dst[d++] = '\\'; dst[d++] = 'f';
        } else if (c == '\n') {
            if (d + 2 >= dst_size) return -1;
            dst[d++] = '\\'; dst[d++] = 'n';
        } else if (c == '\r') {
            if (d + 2 >= dst_size) return -1;
            dst[d++] = '\\'; dst[d++] = 'r';
        } else if (c == '\t') {
            if (d + 2 >= dst_size) return -1;
            dst[d++] = '\\'; dst[d++] = 't';
        } else if (c < 32) {
            if (d + 6 >= dst_size) return -1;
            int n = snprintf(dst + d, dst_size - d, "\\u%04x", c);
            if (n < 0 || (size_t)n >= dst_size - d) return -1;
            d += n;
        } else {
            if (d + 1 >= dst_size) return -1;
            dst[d++] = (char)c;
        }
    }
    if (d >= dst_size) return -1;
    dst[d] = '\0';
    return (int)d;
}

static int write_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int parse_auth_status(const char *json, size_t len)
{
    if (!json || len == 0) return 0;

    const char *p = json;
    while ((p = strstr(p, "\"status\"")) != NULL) {
        p += 8; // skip "status"
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':') {
            p++;
        }
        if (*p == '"') {
            p++;
            if (strncmp(p, "SUCCESS\"", 8) == 0) {
                return 1;
            } else if (strncmp(p, "NO_GRANT\"", 9) == 0) {
                return 2;
            } else {
                return 0;
            }
        }
    }
    return 0;
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

    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_ERR, "pam_tether: socket path length exceeds buffer");
        close(fd);
        return PAM_SERVICE_ERR;
    }
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_DEBUG, "pam_tether: connect(%s) failed: %m", socket_path);
        close(fd);
        return PAM_AUTHINFO_UNAVAIL;
    }

    // Verify peer identity via SO_PEERCRED (Strict Fail-Closed)
    struct ucred cred;
    socklen_t cred_len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0 || cred_len != sizeof(cred)) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_ERR, "pam_tether: failed to retrieve SO_PEERCRED: %m");
        close(fd);
        return PAM_AUTHINFO_UNAVAIL;
    }

    uid_t caller_uid = geteuid();
    if (cred.uid != 0 && cred.uid != caller_uid) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_ERR, "pam_tether: peer UID %u unauthorized (expected 0 or %u)", cred.uid, caller_uid);
        close(fd);
        return PAM_AUTHINFO_UNAVAIL;
    }

    char esc_user[256];
    char esc_svc[256];
    if (json_escape_string(username, esc_user, sizeof(esc_user)) < 0 ||
        json_escape_string(service, esc_svc, sizeof(esc_svc)) < 0) {
        close(fd);
        return PAM_SERVICE_ERR;
    }

    char req_json[1024];
    int json_len = snprintf(req_json, sizeof(req_json),
        "{\"action\":\"AUTH_REQUEST\",\"user\":\"%s\",\"service\":\"%s\"}",
        esc_user, esc_svc);

    secure_clean(esc_user, sizeof(esc_user));
    secure_clean(esc_svc, sizeof(esc_svc));

    if (json_len <= 0 || (size_t)json_len >= sizeof(req_json)) {
        close(fd);
        return PAM_SERVICE_ERR;
    }

    uint32_t len_be = htonl((uint32_t)json_len);
    if (write_all(fd, &len_be, 4) < 0 || write_all(fd, req_json, (size_t)json_len) < 0) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_WARNING, "pam_tether: write to socket failed: %m");
        secure_clean(req_json, sizeof(req_json));
        close(fd);
        return PAM_AUTHINFO_UNAVAIL;
    }
    secure_clean(req_json, sizeof(req_json));

    uint32_t resp_len_be = 0;
    if (read_all(fd, &resp_len_be, 4) < 0) {
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

    if (read_all(fd, resp_buf, resp_len) < 0) {
        secure_clean(resp_buf, resp_len + 1);
        free(resp_buf);
        close(fd);
        return PAM_AUTHINFO_UNAVAIL;
    }
    close(fd);

    resp_buf[resp_len] = '\0';

    int status_code = parse_auth_status(resp_buf, resp_len);
    int auth_result = PAM_AUTH_ERR;
    if (status_code == 1) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_INFO, "pam_tether: authentication successful for user '%s'", username);
        auth_result = PAM_SUCCESS;
    } else if (status_code == 2) {
        if (debug) syslog(LOG_AUTHPRIV | LOG_DEBUG, "pam_tether: no active mobile unlock grant for user '%s'", username);
        auth_result = PAM_AUTHINFO_UNAVAIL;
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

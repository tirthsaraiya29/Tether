#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <security/pam_modules.h>

// Forward declarations of pam_tether functions
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv);

// Mock PAM handle structure
struct pam_handle {
    char user[64];
    char service[64];
};

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
    (void)prompt;
    if (pamh->user[0] == '\0') return PAM_USER_UNKNOWN;
    *user = pamh->user;
    return PAM_SUCCESS;
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item)
{
    if (item_type == PAM_SERVICE) {
        *item = pamh->service;
        return PAM_SUCCESS;
    }
    return PAM_BAD_ITEM;
}

static char g_test_sock_path[100];
static volatile int g_mock_server_running = 0;
static const char *g_expected_user = "testuser";
static int g_simulate_timeout = 0;

static void *mock_server_thread(void *arg)
{
    (void)arg;
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(sfd >= 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_test_sock_path);
    unlink(g_test_sock_path);

    int r = bind(sfd, (struct sockaddr *)&addr, sizeof(addr));
    assert(r == 0);
    r = listen(sfd, 5);
    assert(r == 0);

    g_mock_server_running = 1;

    while (g_mock_server_running) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sfd, &fds);
        int sel = select(sfd + 1, &fds, NULL, NULL, &tv);
        if (sel <= 0) continue;

        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;

        if (g_simulate_timeout) {
            sleep(3);
            close(cfd);
            continue;
        }

        uint32_t req_len_be;
        if (read(cfd, &req_len_be, 4) == 4) {
            uint32_t req_len = ntohl(req_len_be);
            char *req_buf = malloc(req_len + 1);
            if (req_buf) {
                size_t rd = 0;
                while (rd < req_len) {
                    ssize_t chunk = read(cfd, req_buf + rd, req_len - rd);
                    if (chunk <= 0) break;
                    rd += chunk;
                }
                req_buf[rd] = '\0';

                char search_needle[128];
                snprintf(search_needle, sizeof(search_needle), "\"user\":\"%s\"", g_expected_user);

                const char *resp = (strstr(req_buf, search_needle) != NULL)
                    ? "{\"status\":\"SUCCESS\"}"
                    : "{\"status\":\"DENIED\"}";

                uint32_t resp_len = strlen(resp);
                uint32_t resp_len_be = htonl(resp_len);
                ssize_t w1 = write(cfd, &resp_len_be, 4);
                ssize_t w2 = write(cfd, resp, resp_len);
                (void)w1;
                (void)w2;

                free(req_buf);
            }
        }
        close(cfd);
    }

    close(sfd);
    unlink(g_test_sock_path);
    return NULL;
}

int main(void)
{
    printf("=== Running Native pam_tether Test Suite ===\n");

    snprintf(g_test_sock_path, sizeof(g_test_sock_path), "/tmp/tether_pam_%d.sock", getpid());

    pthread_t th;
    pthread_create(&th, NULL, mock_server_thread, NULL);
    while (!g_mock_server_running) usleep(10000);

    struct pam_handle pamh;
    memset(&pamh, 0, sizeof(pamh));
    snprintf(pamh.user, sizeof(pamh.user), "testuser");
    snprintf(pamh.service, sizeof(pamh.service), "sudo");

    char sock_arg[128];
    snprintf(sock_arg, sizeof(sock_arg), "socket=%s", g_test_sock_path);
    const char *argv_valid[] = { sock_arg, "timeout=2", "debug" };

    // Test 1: Successful authentication for expected user
    printf("[1/5] Testing PAM_SUCCESS for valid user... ");
    int rc = pam_sm_authenticate(&pamh, 0, 3, argv_valid);
    assert(rc == PAM_SUCCESS);
    printf("PASSED\n");

    // Test 2: Denied authentication for different user
    printf("[2/5] Testing PAM_AUTH_ERR for unauthorized user... ");
    snprintf(pamh.user, sizeof(pamh.user), "intruder");
    rc = pam_sm_authenticate(&pamh, 0, 3, argv_valid);
    assert(rc == PAM_AUTH_ERR);
    printf("PASSED\n");

    // Test 3: Unavailable daemon / missing socket
    printf("[3/5] Testing PAM_AUTHINFO_UNAVAIL when socket missing... ");
    const char *argv_missing[] = { "socket=/tmp/nonexistent_socket_tether.sock", "timeout=1" };
    rc = pam_sm_authenticate(&pamh, 0, 2, argv_missing);
    assert(rc == PAM_AUTHINFO_UNAVAIL);
    printf("PASSED\n");

    // Test 4: Timeout handling
    printf("[4/5] Testing socket timeout handling... ");
    g_simulate_timeout = 1;
    snprintf(pamh.user, sizeof(pamh.user), "testuser");
    const char *argv_short_timeout[] = { sock_arg, "timeout=1" };
    rc = pam_sm_authenticate(&pamh, 0, 2, argv_short_timeout);
    assert(rc == PAM_AUTHINFO_UNAVAIL || rc == PAM_AUTH_ERR);
    g_simulate_timeout = 0;
    printf("PASSED\n");

    // Test 5: pam_sm_setcred & acct_mgmt
    printf("[5/5] Testing pam_sm_setcred and pam_sm_acct_mgmt... ");
    assert(pam_sm_setcred(&pamh, 0, 3, argv_valid) == PAM_SUCCESS);
    assert(pam_sm_acct_mgmt(&pamh, 0, 3, argv_valid) == PAM_SUCCESS);
    printf("PASSED\n");

    g_mock_server_running = 0;
    pthread_join(th, NULL);

    printf("All pam_tether native tests passed successfully!\n");
    return 0;
}

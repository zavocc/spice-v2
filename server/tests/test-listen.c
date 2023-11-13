/* -*- Mode: C; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
   Copyright (C) 2018 Red Hat, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
/*
 * This tests the external API entry points to configure the address/port
 * spice-server is listening on
 */
#include <config.h>

#include "basic-event-loop.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "test-glib-compat.h"

/* Arbitrary base port, we want a port which is not in use by the system, and
 * by another of our tests (in case of parallel runs)
 */
#define BASE_PORT 5728

#define PKI_DIR SPICE_TOP_SRCDIR "/server/tests/pki/"

typedef struct {
    SpiceCoreInterface *core;
    SpiceTimer *exit_mainloop_timer;
    SpiceTimer *timeout_timer;
} TestEventLoop;

static void timeout_cb(SPICE_GNUC_UNUSED void *opaque)
{
    g_assert_not_reached();
}

static void exit_mainloop_cb(SPICE_GNUC_UNUSED void *opaque)
{
    basic_event_loop_quit();
}

static void test_event_loop_quit(TestEventLoop *event_loop)
{
    event_loop->core->timer_start(event_loop->exit_mainloop_timer, 0);
}

static void test_event_loop_init(TestEventLoop *event_loop)
{
    event_loop->core = basic_event_loop_init();
    event_loop->timeout_timer = event_loop->core->timer_add(timeout_cb, NULL);
    event_loop->exit_mainloop_timer = event_loop->core->timer_add(exit_mainloop_cb, NULL);
}

static void test_event_loop_destroy(TestEventLoop *event_loop)
{
    if (event_loop->timeout_timer != NULL) {
        event_loop->core->timer_remove(event_loop->timeout_timer);
        event_loop->timeout_timer = NULL;
    }
    if (event_loop->exit_mainloop_timer != NULL) {
        event_loop->core->timer_remove(event_loop->exit_mainloop_timer);
        event_loop->exit_mainloop_timer = NULL;
    }
    basic_event_loop_destroy();
    event_loop->core = NULL;
}

static void test_event_loop_run(TestEventLoop *event_loop)
{
    event_loop->core->timer_start(event_loop->timeout_timer, 50000);
    basic_event_loop_mainloop();
}

static BIO *fake_client_connect(const char *hostname, int port, bool use_tls)
{
    if (port < 0) {
#ifndef _WIN32
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strcpy(addr.sun_path, hostname);
        if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            close(sock);
            return NULL;
        }
        return BIO_new_fd(sock, 0);
#else
        g_assert_not_reached();
#endif
    }

    char con_buf[256];
    g_snprintf(con_buf, sizeof(con_buf), "%s:%d", hostname, port);

    SSL_CTX *ctx = NULL;
    BIO *bio;
    if (use_tls) {
        ctx = SSL_CTX_new(TLS_client_method());
        g_assert_nonnull(ctx);

        bio = BIO_new_ssl_connect(ctx);
        g_assert_nonnull(bio);

        BIO_set_conn_hostname(bio, con_buf);
    } else {
        bio = BIO_new_connect(con_buf);
        g_assert_nonnull(bio);
    }

    if (BIO_do_connect(bio) <= 0) {
        BIO_free(bio);
        bio = NULL;
    }

    SSL_CTX_free(ctx);
    return bio;
}

static void check_magic(BIO *bio)
{
    uint8_t buffer[4];

    /* send dummy data to trigger a response from the server */
    memset(buffer, 0xa5, G_N_ELEMENTS(buffer));
    g_assert_cmpint(BIO_write(bio, buffer, G_N_ELEMENTS(buffer)), ==, G_N_ELEMENTS(buffer));

    g_assert_cmpint(BIO_read(bio, buffer, G_N_ELEMENTS(buffer)), ==, G_N_ELEMENTS(buffer));
    g_assert_cmpint(memcmp(buffer, "REDQ", 4), ==, 0);
}

typedef struct
{
    const char *hostname;
    int port;
    bool use_tls;
    TestEventLoop *event_loop;
} ThreadData;

static gpointer check_magic_thread(gpointer data)
{
    ThreadData *thread_data = (ThreadData*) data;
    BIO *bio;

    bio = fake_client_connect(thread_data->hostname, thread_data->port, thread_data->use_tls);
    g_assert_nonnull(bio);
    check_magic(bio);

    BIO_free_all(bio);

    test_event_loop_quit(thread_data->event_loop);
    g_free(thread_data);

    return NULL;
}

static gpointer check_no_connect_thread(gpointer data)
{
    ThreadData *thread_data = (ThreadData*) data;

    BIO *bio = fake_client_connect(thread_data->hostname, thread_data->port, false);
    g_assert_null(bio);

    test_event_loop_quit(thread_data->event_loop);
    g_free(thread_data);

    return NULL;
}

static GThread *fake_client_new(GThreadFunc thread_func,
                                const char *hostname, int port,
                                bool use_tls,
                                TestEventLoop *event_loop)
{
    ThreadData *thread_data = g_new0(ThreadData, 1);

    if (port == -1) {
#ifdef _WIN32
        g_assert_not_reached();
#endif
    } else {
        g_assert_cmpuint(port, >, 0);
        g_assert_cmpuint(port, <, 65536);
    }
    thread_data->hostname = hostname;
    thread_data->port = port;
    thread_data->use_tls = use_tls;
    thread_data->event_loop = event_loop;

    /* check_magic_thread will assume ownership of 'connectable' */
    return g_thread_new("fake-client-thread", thread_func, thread_data);
}

static void test_connect_plain(void)
{
    GThread *thread;
    int result;

    TestEventLoop event_loop = { 0, };

    test_event_loop_init(&event_loop);

    /* server */
    SpiceServer *server = spice_server_new();
    spice_server_set_name(server, "SPICE listen test");
    spice_server_set_noauth(server);
    spice_server_set_port(server, BASE_PORT);
    result = spice_server_init(server, event_loop.core);
    g_assert_cmpint(result, ==, 0);

    /* fake client */
    thread = fake_client_new(check_magic_thread, "localhost", BASE_PORT, false, &event_loop);
    test_event_loop_run(&event_loop);
    g_assert_null(g_thread_join(thread));

    test_event_loop_destroy(&event_loop);
    spice_server_destroy(server);
}

static void test_connect_tls(void)
{
    GThread *thread;
    int result;

    TestEventLoop event_loop = { 0, };

    test_event_loop_init(&event_loop);

    /* server */
    SpiceServer *server = spice_server_new();
    spice_server_set_name(server, "SPICE listen test");
    spice_server_set_noauth(server);
    result = spice_server_set_tls(server, BASE_PORT,
                                  PKI_DIR "ca-cert.pem",
                                  PKI_DIR "server-cert.pem",
                                  PKI_DIR "server-key.pem",
                                  NULL, NULL, NULL);
    g_assert_cmpint(result, ==, 0);
    result = spice_server_init(server, event_loop.core);
    g_assert_cmpint(result, ==, 0);

    /* fake client */
    thread = fake_client_new(check_magic_thread, "localhost", BASE_PORT, true, &event_loop);
    test_event_loop_run(&event_loop);
    g_assert_null(g_thread_join(thread));

    test_event_loop_destroy(&event_loop);
    spice_server_destroy(server);
}

static void test_connect_plain_and_tls(void)
{
    GThread *thread;
    int result;

    TestEventLoop event_loop = { 0, };

    test_event_loop_init(&event_loop);

    /* server */
    SpiceServer *server = spice_server_new();
    spice_server_set_name(server, "SPICE listen test");
    spice_server_set_noauth(server);
    spice_server_set_port(server, BASE_PORT);
    result = spice_server_set_tls(server, BASE_PORT+1,
                                  PKI_DIR "ca-cert.pem",
                                  PKI_DIR "server-cert.pem",
                                  PKI_DIR "server-key.pem",
                                  NULL, NULL, NULL);
    g_assert_cmpint(result, ==, 0);
    result = spice_server_init(server, event_loop.core);
    g_assert_cmpint(result, ==, 0);

    /* fake client */
    thread = fake_client_new(check_magic_thread, "localhost", BASE_PORT, false, &event_loop);
    test_event_loop_run(&event_loop);
    g_assert_null(g_thread_join(thread));

    thread = fake_client_new(check_magic_thread, "localhost", BASE_PORT+1, true, &event_loop);
    test_event_loop_run(&event_loop);
    g_assert_null(g_thread_join(thread));

    test_event_loop_destroy(&event_loop);
    spice_server_destroy(server);
}

#ifndef _WIN32
static void test_connect_unix(void)
{
    GThread *thread;
    int result;

    TestEventLoop event_loop = { 0, };

    test_event_loop_init(&event_loop);

    /* server */
    SpiceServer *server = spice_server_new();
    spice_server_set_name(server, "SPICE listen test");
    spice_server_set_noauth(server);
    spice_server_set_addr(server, "test-listen.unix", SPICE_ADDR_FLAG_UNIX_ONLY);
    result = spice_server_init(server, event_loop.core);
    g_assert_cmpint(result, ==, 0);

    /* fake client */
    thread = fake_client_new(check_magic_thread, "test-listen.unix", -1, false, &event_loop);
    test_event_loop_run(&event_loop);
    g_assert_null(g_thread_join(thread));

    test_event_loop_destroy(&event_loop);
    spice_server_destroy(server);
}
#endif

static void test_connect_ko(void)
{
    GThread *thread;
    TestEventLoop event_loop = { 0, };

    test_event_loop_init(&event_loop);

    /* fake client */
    thread = fake_client_new(check_no_connect_thread, "localhost", BASE_PORT, false, &event_loop);
    test_event_loop_run(&event_loop);
    g_assert_null(g_thread_join(thread));

    test_event_loop_destroy(&event_loop);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/server/listen/connect_plain", test_connect_plain);
    g_test_add_func("/server/listen/connect_tls", test_connect_tls);
    g_test_add_func("/server/listen/connect_both", test_connect_plain_and_tls);
#ifndef _WIN32
    g_test_add_func("/server/listen/connect_unix", test_connect_unix);
#endif
    g_test_add_func("/server/listen/connect_ko", test_connect_ko);

    return g_test_run();
}

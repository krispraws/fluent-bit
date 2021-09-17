/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/tls/flb_tls.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

/*
 * OPENSSL_VERSION_NUMBER has the following semantics
 *
 *     0x010100000L   M = major  F = fix    S = status
 *       MMNNFFPPS    N = minor  P = patch
 */
#define OPENSSL_1_1_0 0x010100000L

/*
 * RHEL-family distrbutions do not provide system certificates in
 * a format that OpenSSL's CAPath can read, but do provide a single
 * packed cert in /etc/certs.
 *
 * Use the bundled cert as the default trusted CA.
 */
#define RHEL_DEFAULT_CA "/etc/ssl/certs/ca-bundle.crt"

/* OpenSSL library context */
struct tls_context {
    int debug_level;
    SSL_CTX *ctx;
    pthread_mutex_t mutex;
};

struct tls_session {
    SSL *ssl;
    int fd;
    struct tls_context *parent;    /* parent struct tls_context ref */
};

/*
 * Short summary of error handling for OpenSSL apis
 * ------------------------------------------------
 * This applies to OpenSSL v1.1.0 as well as older versions.
 * https://www.openssl.org/docs/man1.1.0/man3/SSL_get_error.html
 *
 * 1. Error details are stored in multiple places. Return codes from
 * SSL_connect, SSL_read etc. must be passed to SSL_get_error to get the
 * real failure error code. There is also an error queue per thread that
 * contains more details and must be cleared before every SSL I/O call in order
 * for SSL_get_error to work reliably. For SSL_ERROR_SYSCALL, errno may hold
 * the real error code if the BIO is socket based.
 *
 * 2. The error codes returned from SSL_get_error can be positive and must be
 * translated before returning it to callers that treat a positive value as
 * success e.g. read and write functions that expect positive return values to
 * be number of bytes read or written.
 *
 * 3. SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE can both be returned from
 * any TLS/SSl I/O function.
 */

/*
 * Callback for ERR_print_errors_cb to traverse the entire OpenSSL error queue.
 * ERR_print_errors_cb also removes the entry from the queue.
 */
static int openssl_error_queue_callback(const char *err_str,
                                        size_t err_str_len,
                                        void *user_data)
{
    const char* log_prefix_str = user_data;

    if (log_prefix_str) {
        flb_error("[openssl] %s error queue entry=%.*s",
                  log_prefix_str, err_str_len, err_str);
    } else {
        flb_error("[openssl] error queue entry=%.*s", err_str_len, err_str);
    }
    return 0;
}

/* Log and clear the OpenSSL error queue. Log errno in some cases. */
static void log_non_retryable_openssl_error(const char* log_prefix, int ssl_err)
{
    char buf[256] = {0};

    ERR_print_errors_cb(openssl_error_queue_callback, (void *) log_prefix);
    /* Some error codes like SSL_ERROR_SYSCALL indicate that the real reason
    may be in errno */
    if (ssl_err == SSL_ERROR_SYSCALL) {
        strerror_r(errno, buf, sizeof(buf) - 1);
        flb_warn("[openssl] %s ssl_err=%i errno=%i err=%s",
                 log_prefix, ssl_err, errno, buf);
    }
}

static int tls_init(void)
{
/*
 * Explicit initialization is needed for older versions of
 * OpenSSL (before v1.1.0).
 *
 * https://wiki.openssl.org/index.php/Library_Initialization
 */
#if OPENSSL_VERSION_NUMBER < OPENSSL_1_1_0
    OPENSSL_add_all_algorithms_noconf();
    SSL_load_error_strings();
    SSL_library_init();
#endif
    return 0;
}

static void tls_info_callback(const SSL *s, int where, int ret)
{
    int w;
    int fd;
    const char *str;

    fd = SSL_get_fd(s);
    w = where & ~SSL_ST_MASK;
    if (w & SSL_ST_CONNECT) {
        str = "SSL_connect";
    }
    else if (w & SSL_ST_ACCEPT) {
        str = "SSL_accept";
    }
    else {
        str = "undefined";
    }

    if (where & SSL_CB_LOOP) {
        flb_debug("[tls] connection #%i %s: %s",
                  fd, str, SSL_state_string_long(s));
    }
    else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        flb_debug("[tls] connection #%i SSL3 alert %s:%s:%s",
                  fd, str,
                  SSL_alert_type_string_long(ret),
                  SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            flb_error("[tls] connection #%i %s: failed in %s",
                      fd, str, SSL_state_string_long(s));
        }
        else if (ret < 0) {
            ret = SSL_get_error(s, ret);
            if (ret == SSL_ERROR_WANT_WRITE) {
                flb_debug("[tls] connection #%i WANT_WRITE", fd);
            }
            else if (ret == SSL_ERROR_WANT_READ) {
                flb_debug("[tls] connection #%i WANT_READ", fd);
            }
            else {
                flb_error("[tls] connection #%i %s: error in %s",
                          fd, str, SSL_state_string_long(s));
            }
        }
    }
}

static void tls_context_destroy(void *ctx_backend)
{
    struct tls_context *ctx = ctx_backend;

    pthread_mutex_lock(&ctx->mutex);
    SSL_CTX_free(ctx->ctx);
    pthread_mutex_unlock(&ctx->mutex);

    flb_free(ctx);
}

static int load_system_certificates(struct tls_context *ctx)
{
    int ret;
    const char ca_path[] = "/etc/ssl/certs/";

    /* For Windows use specific API to read the certs store */
#ifdef _MSC_VER
    //return windows_load_system_certificates(ctx);
#endif

    if (access(RHEL_DEFAULT_CA, R_OK) == 0) {
        ret = SSL_CTX_load_verify_locations(ctx->ctx, RHEL_DEFAULT_CA, ca_path);
    }
    else {
        ret = SSL_CTX_load_verify_locations(ctx->ctx, NULL, ca_path);
    }

    if (ret != 1) {
        ERR_print_errors_fp(stderr);
    }
    return 0;
}

static void *tls_context_create(int verify, int debug,
                                const char *vhost,
                                const char *ca_path,
                                const char *ca_file, const char *crt_file,
                                const char *key_file, const char *key_passwd)
{
    int ret;
    SSL_CTX *ssl_ctx;
    struct tls_context *ctx;
    unsigned long sslq_err = 0;

    /*
     * Init library ? based in the documentation on OpenSSL >= 1.1.0 is not longer
     * necessary since the library will initialize it self:
     *
     * https://wiki.openssl.org/index.php/Library_Initialization
     */

    /* Create OpenSSL context */
#if OPENSSL_VERSION_NUMBER < OPENSSL_1_1_0
    /*
     * SSLv23_method() is actually an equivalent of TLS_client_method()
     * in OpenSSL v1.0.x.
     *
     * https://www.openssl.org/docs/man1.0.2/man3/SSLv23_method.html
     */
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#else
    ssl_ctx = SSL_CTX_new(TLS_client_method());
#endif
    if (!ssl_ctx) {
        flb_error("[openssl] could not create context");
        return NULL;
    }

    ctx = flb_calloc(1, sizeof(struct tls_context));
    if (!ctx) {
        flb_errno();
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }
    ctx->ctx = ssl_ctx;
    ctx->debug_level = debug;
    pthread_mutex_init(&ctx->mutex, NULL);

    /* Verify peer: by default OpenSSL always verify peer */
    if (verify == FLB_FALSE) {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    }
    else {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    }

    /* ca_path | ca_file */
    if (ca_path) {
        ret = SSL_CTX_load_verify_locations(ctx->ctx, NULL, ca_path);
        if (ret != 1) {
            sslq_err = ERR_get_error();
            flb_error("[tls] ca_path'%s' %lu: %s",
                      ca_path,
                      sslq_err,
                      ERR_error_string(sslq_err, NULL));
            goto error;
        }
    }
    else if (ca_file) {
        ret = SSL_CTX_load_verify_locations(ctx->ctx, ca_file, NULL);
        if (ret != 1) {
            sslq_err = ERR_get_error();
            flb_error("[tls] ca_file '%s' %lu: %s",
                      ca_file,
                      sslq_err,
                      ERR_error_string(sslq_err, NULL));
            goto error;
        }
    }
    else {
        load_system_certificates(ctx);
    }

    /* crt_file */
    if (crt_file) {
        ret = SSL_CTX_use_certificate_chain_file(ssl_ctx, crt_file);
		if (ret != 1) {
            sslq_err = ERR_get_error();
            flb_error("[tls] crt_file '%s' %lu: %s",
                      crt_file,
                      sslq_err,
                      ERR_error_string(sslq_err, NULL));
            goto error;
        }
    }

    /* key_file */
    if (key_file) {
        if (key_passwd) {
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx,
                                                   (void *) key_passwd);
        }
        ret = SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file,
                                          SSL_FILETYPE_PEM);
        if (ret != 1) {
            sslq_err = ERR_get_error();
            flb_error("[tls] key_file '%s' %lu: %s",
                      key_file,
                      sslq_err,
                      ERR_error_string(sslq_err, NULL));
        }

        /* Make sure the key and certificate file match */
        if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
            flb_error("[tls] private_key '%s' and password don't match",
                      key_file);
            goto error;
        }
    }

    return ctx;

 error:
    tls_context_destroy(ctx);
    return NULL;
}

static void *tls_session_create(struct flb_tls *tls,
                                struct flb_upstream_conn *u_conn)
{
    struct tls_session *session;
    struct tls_context *ctx = tls->ctx;
    SSL *ssl;

    session = flb_calloc(1, sizeof(struct tls_session));
    if (!session) {
        flb_errno();
        return NULL;
    }
    session->parent = ctx;

    pthread_mutex_lock(&ctx->mutex);
    ssl = SSL_new(ctx->ctx);

    if (!ssl) {
        flb_error("[openssl] could not create new SSL context");
        flb_free(session);
        pthread_mutex_unlock(&ctx->mutex);
        return NULL;
    }
    session->ssl = ssl;
    session->fd = u_conn->fd;
    SSL_set_fd(ssl, u_conn->fd);

    /*
     * TLS Debug Levels:
     *
     *  0: No debug,
     *  1: Error
     *  2: State change
     *  3: Informational
     *  4: Verbose
     */
    if (tls->debug == 1) {
        SSL_set_info_callback(session->ssl, tls_info_callback);
    }
    SSL_set_connect_state(ssl);
    pthread_mutex_unlock(&ctx->mutex);
    return session;
}

static int tls_session_destroy(void *session)
{
    struct tls_session *ptr = session;
    struct tls_context *ctx;

    if (!ptr) {
        return 0;
    }
    ctx = ptr->parent;

    pthread_mutex_lock(&ctx->mutex);

    if (flb_socket_error(ptr->fd) == 0) {
        SSL_shutdown(ptr->ssl);
    }
    SSL_free(ptr->ssl);
    flb_free(ptr);

    pthread_mutex_unlock(&ctx->mutex);

    return 0;
}

static int tls_net_read(struct flb_upstream_conn *u_conn,
                        void *buf, size_t len)
{
    int ret;
    struct tls_session *session = (struct tls_session *) u_conn->tls_session;
    struct tls_context *ctx;
    int ssl_err = SSL_ERROR_NONE;
    int fd = -1;
    char log_prefix[256] = {0};

    ctx = session->parent;
    pthread_mutex_lock(&ctx->mutex);

    /* Clear the current thread's error queue */
    ERR_clear_error();
    fd = SSL_get_fd(session->ssl);
    snprintf(log_prefix, sizeof(log_prefix) - 1, "[fd=%i] SSL_read", fd);

    ret = SSL_read(session->ssl, buf, len);
    if (ret <= 0) {
        ssl_err = SSL_get_error(session->ssl, ret);

        if (ssl_err == SSL_ERROR_WANT_READ) {
            ret = FLB_TLS_WANT_READ;
        }
        else {
            flb_error("[openssl] %s non-retryable error: ret=%i, ssl_err=%i", log_prefix, ret, ssl_err);
            log_non_retryable_openssl_error(log_prefix, ssl_err);
            ret = -1;
        }
    }

    pthread_mutex_unlock(&ctx->mutex);
    return ret;
}

static int tls_net_write(struct flb_upstream_conn *u_conn,
                         const void *data, size_t len)
{
    int ret;
    size_t total = 0;
    struct tls_session *session = (struct tls_session *) u_conn->tls_session;
    struct tls_context *ctx;
    int ssl_err = SSL_ERROR_NONE;
    int fd = -1;
    char log_prefix[256] = {0};

    ctx = session->parent;
    pthread_mutex_lock(&ctx->mutex);

    /* Clear the current thread's error queue */
    ERR_clear_error();
    fd = SSL_get_fd(session->ssl);
    snprintf(log_prefix, sizeof(log_prefix) - 1, "[fd=%i] SSL_write", fd);

    ret = SSL_write(session->ssl,
                    (unsigned char *) data + total,
                    len - total);
    if (ret <= 0) {
        ssl_err = SSL_get_error(session->ssl, ret);
        if (ssl_err == SSL_ERROR_WANT_WRITE) {
            ret = FLB_TLS_WANT_WRITE;
        } else if (ssl_err == SSL_ERROR_WANT_READ) {
            ret = FLB_TLS_WANT_READ;
        } else {
            flb_error("[openssl] %s non-retryable error: ret=%i, ssl_err=%i", log_prefix, ret, ssl_err);
            log_non_retryable_openssl_error(log_prefix, ssl_err);
            ret = -1;
        }
    }

    pthread_mutex_unlock(&ctx->mutex);

    /* Update counter and check if we need to continue writing */
    return ret;
}

static int tls_net_handshake(struct flb_tls *tls, void *ptr_session)
{
    int ret = 0;
    struct tls_session *session = ptr_session;
    struct tls_context *ctx;
    int ssl_err = SSL_ERROR_NONE;
    int fd = -1;
    char log_prefix[256] = {0};

    ctx = session->parent;
    pthread_mutex_lock(&ctx->mutex);

    /* Clear the current thread's error queue */
    ERR_clear_error();
    fd = SSL_get_fd(session->ssl);
    snprintf(log_prefix, sizeof(log_prefix) - 1, "[fd=%i] SSL_connect", fd);

    if (tls->vhost) {
        SSL_set_tlsext_host_name(session->ssl, tls->vhost);
    }

    ret = SSL_connect(session->ssl);
    if (ret != 1) {
        ssl_err = SSL_get_error(session->ssl, ret);
        if (ssl_err == SSL_ERROR_WANT_WRITE) {
            ret = FLB_TLS_WANT_WRITE;
        }
        else if (ssl_err == SSL_ERROR_WANT_READ) {
            ret = FLB_TLS_WANT_READ;
        }
        else {
            flb_error("[openssl] %s non-retryable error: ret=%i, ssl_err=%i", log_prefix, ret, ssl_err);
            log_non_retryable_openssl_error(log_prefix, ssl_err);
            ret = -1;
        }
    }
    else {
        flb_trace("[openssl] %s connection and handshake OK", log_prefix);
        ret = 0;
    }

    pthread_mutex_unlock(&ctx->mutex);
    return ret;
}

/* OpenSSL backend registration */
static struct flb_tls_backend tls_openssl = {
    .name            = "openssl",
    .context_create  = tls_context_create,
    .context_destroy = tls_context_destroy,
    .session_create  = tls_session_create,
    .session_destroy = tls_session_destroy,
    .net_read        = tls_net_read,
    .net_write       = tls_net_write,
    .net_handshake   = tls_net_handshake
};

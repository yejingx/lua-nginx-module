
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) Jing Ye (yejingx)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#if (NGX_HTTP_SSL)


#include "ngx_http_lua_cache.h"
#include "ngx_http_lua_initworkerby.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_ssl_module.h"
#include "ngx_http_lua_contentby.h"
#include "ngx_http_lua_ssl_signby.h"
#include "ngx_http_lua_directive.h"


static void ngx_http_lua_ssl_sign_done(void *data);
static void ngx_http_lua_ssl_sign_aborted(void *data);
static u_char *ngx_http_lua_log_ssl_sign_error(ngx_log_t *log, u_char *buf,
    size_t len);
static ngx_int_t ngx_http_lua_ssl_sign_by_chunk(lua_State *L,
    ngx_http_request_t *r);


int ngx_http_lua_ssl_sign_ctx_index = -1;


ngx_int_t
ngx_http_lua_ssl_sign_handler_file(ngx_http_request_t *r,
    ngx_http_lua_srv_conf_t *lscf, lua_State *L)
{
    ngx_int_t           rc;

    rc = ngx_http_lua_cache_loadfile(r->connection->log, L,
                                     lscf->ssl.sign.src.data,
                                     lscf->ssl.sign.src_key);
    if (rc != NGX_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    ngx_http_lua_assert(lua_isfunction(L, -1));

    return ngx_http_lua_ssl_sign_by_chunk(L, r);
}


ngx_int_t
ngx_http_lua_ssl_sign_handler_inline(ngx_http_request_t *r,
    ngx_http_lua_srv_conf_t *lscf, lua_State *L)
{
    ngx_int_t           rc;

    rc = ngx_http_lua_cache_loadbuffer(r->connection->log, L,
                                       lscf->ssl.sign.src.data,
                                       lscf->ssl.sign.src.len,
                                       lscf->ssl.sign.src_key,
                                       "=ssl_sign_by_lua");
    if (rc != NGX_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    ngx_http_lua_assert(lua_isfunction(L, -1));

    return ngx_http_lua_ssl_sign_by_chunk(L, r);
}


char *
ngx_http_lua_ssl_sign_by_lua_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char        *rv;
    ngx_conf_t   save;

    save = *cf;
    cf->handler = ngx_http_lua_ssl_sign_by_lua;
    cf->handler_conf = conf;

    rv = ngx_http_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
ngx_http_lua_ssl_sign_by_lua(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
#if OPENSSL_VERSION_NUMBER < 0x1000205fL

    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                  "at least OpenSSL 1.0.2e required but found "
                  OPENSSL_VERSION_TEXT);

    return NGX_CONF_ERROR;

#else
    u_char                      *p;
    u_char                      *name;
    ngx_str_t                   *value;
    ngx_http_lua_srv_conf_t    *lscf = conf;

    dd("enter");

    /*  must specifiy a content handler */
    if (cmd->post == NULL) {
        return NGX_CONF_ERROR;
    }

    if (lscf->ssl.sign.handler) {
        return "is duplicate";
    }

    if (ngx_http_lua_ssl_sign_ctx_index == -1) {
        ngx_http_lua_ssl_sign_ctx_index =
            SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

        if (ngx_ssl_connection_index == -1) {
            ngx_ssl_error(NGX_LOG_ALERT, cf->log, 0,
                          "lua: SSL_get_ex_new_index() failed");
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    lscf->ssl.sign.handler = (ngx_http_lua_srv_conf_handler_pt) cmd->post;

    if (cmd->post == ngx_http_lua_ssl_sign_handler_file) {
        /* Lua code in an external file */

        name = ngx_http_lua_rebase_path(cf->pool, value[1].data,
                                        value[1].len);
        if (name == NULL) {
            return NGX_CONF_ERROR;
        }

        lscf->ssl.sign.src.data = name;
        lscf->ssl.sign.src.len = ngx_strlen(name);

        p = ngx_palloc(cf->pool, NGX_HTTP_LUA_FILE_KEY_LEN + 1);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        lscf->ssl.sign.src_key = p;

        p = ngx_copy(p, NGX_HTTP_LUA_FILE_TAG, NGX_HTTP_LUA_FILE_TAG_LEN);
        p = ngx_http_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';

    } else {
        /* inlined Lua code */

        lscf->ssl.sign.src = value[1];

        p = ngx_palloc(cf->pool, NGX_HTTP_LUA_INLINE_KEY_LEN + 1);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        lscf->ssl.sign.src_key = p;

        p = ngx_copy(p, NGX_HTTP_LUA_INLINE_TAG, NGX_HTTP_LUA_INLINE_TAG_LEN);
        p = ngx_http_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';
    }

    return NGX_CONF_OK;

#endif  /* OPENSSL_VERSION_NUMBER < 0x1000205fL */
}


int
ngx_http_lua_ssl_sign_handler(ngx_ssl_conn_t *ssl_conn, void *data)
{
    lua_State                       *L;
    ngx_int_t                        rc;
    ngx_connection_t                *c, *fc;
    ngx_http_request_t              *r = NULL;
    ngx_pool_cleanup_t              *cln;
    ngx_http_connection_t           *hc;
    ngx_http_lua_srv_conf_t         *lscf;
    ngx_http_lua_ssl_sign_ctx_t     *cctx;

    c = ngx_ssl_get_connection(ssl_conn);

    dd("c = %p", c);

    cctx = ngx_http_lua_ssl_get_sign_ctx(c->ssl->connection);

    dd("ssl sign handler, sign-ctx=%p", cctx);

    if (cctx) {
        /* not the first time */

        if (cctx->done) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "lua_sign_by_lua: sign cb exit code: %d",
                           cctx->exit_code);

            dd("lua ssl sign done, finally");
            return cctx->exit_code;
        }

        return -1;
    }

    /* cctx == NULL */

    dd("first time");

    hc = c->data;

    fc = ngx_http_lua_create_fake_connection(NULL);
    if (fc == NULL) {
        goto failed;
    }

    fc->log->handler = ngx_http_lua_log_ssl_sign_error;
    fc->log->data = fc;

    fc->addr_text = c->addr_text;
    fc->listening = c->listening;

    r = ngx_http_lua_create_fake_request(fc);
    if (r == NULL) {
        goto failed;
    }

    r->main_conf = hc->conf_ctx->main_conf;
    r->srv_conf = hc->conf_ctx->srv_conf;
    r->loc_conf = hc->conf_ctx->loc_conf;

    fc->log->file = c->log->file;
    fc->log->log_level = c->log->log_level;
    fc->ssl = c->ssl;

    cctx = ngx_pcalloc(c->pool, sizeof(ngx_http_lua_ssl_sign_ctx_t));
    if (cctx == NULL) {
        goto failed;  /* error */
    }

    cctx->exit_code = 1;  /* successful by default */
    cctx->connection = c;
    cctx->request = r;

    dd("setting cctx");

    if (SSL_set_ex_data(c->ssl->connection, ngx_http_lua_ssl_sign_ctx_index,
                        cctx)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_ex_data() failed");
        goto failed;
    }

    lscf = ngx_http_get_module_srv_conf(r, ngx_http_lua_module);

    /* TODO honor lua_code_cache off */
    L = ngx_http_lua_get_lua_vm(r, NULL);

    c->log->action = "loading SSL sign by lua";

    rc = lscf->ssl.sign.handler(r, lscf, L);

    if (rc >= NGX_OK || rc == NGX_ERROR) {
        cctx->done = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "lua_sign_by_lua: handler return value: %i, "
                       "sign cb exit code: %d", rc, cctx->exit_code);

        c->log->action = "SSL handshaking";
        return cctx->exit_code;
    }

    /* rc == NGX_DONE */

    cln = ngx_pool_cleanup_add(fc->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = ngx_http_lua_ssl_sign_done;
    cln->data = cctx;

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = ngx_http_lua_ssl_sign_aborted;
    cln->data = cctx;

    return -1;

#if 1
failed:

    if (r && r->pool) {
        ngx_http_lua_free_fake_request(r);
    }

    if (fc) {
        ngx_http_lua_close_fake_connection(fc);
    }

    return 0;
#endif
}


static void
ngx_http_lua_ssl_sign_done(void *data)
{
    ngx_connection_t                *c;
    ngx_http_lua_ssl_sign_ctx_t     *cctx = data;

    dd("lua ssl sign done");

    if (cctx->aborted) {
        return;
    }

    ngx_http_lua_assert(cctx->done == 0);

    cctx->done = 1;

    c = cctx->connection;

    c->log->action = "SSL handshaking";

    ngx_post_event(c->write, &ngx_posted_events);
}


static void
ngx_http_lua_ssl_sign_aborted(void *data)
{
    ngx_http_lua_ssl_sign_ctx_t     *cctx = data;

    dd("lua ssl sign done");

    if (cctx->done) {
        /* completed successfully already */
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cctx->connection->log, 0,
                   "lua_sign_by_lua: sign cb aborted");

    cctx->aborted = 1;
    cctx->request->connection->ssl = NULL;

    ngx_http_lua_finalize_fake_request(cctx->request, NGX_ERROR);
}


static u_char *
ngx_http_lua_log_ssl_sign_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_connection_t    *c;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    p = ngx_snprintf(buf, len, ", context: ssl_sign_by_lua*");
    len -= p - buf;
    buf = p;

    c = log->data;

    if (c->addr_text.len) {
        p = ngx_snprintf(buf, len, ", client: %V", &c->addr_text);
        len -= p - buf;
        buf = p;
    }

    if (c && c->listening && c->listening->addr_text.len) {
        p = ngx_snprintf(buf, len, ", server: %V", &c->listening->addr_text);
        /* len -= p - buf; */
        buf = p;
    }

    return buf;
}


static ngx_int_t
ngx_http_lua_ssl_sign_by_chunk(lua_State *L, ngx_http_request_t *r)
{
    int                      co_ref;
    ngx_int_t                rc;
    lua_State               *co;
    ngx_http_lua_ctx_t      *ctx;
    ngx_http_cleanup_t      *cln;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    if (ctx == NULL) {
        ctx = ngx_http_lua_create_ctx(r);
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        dd("reset ctx");
        ngx_http_lua_reset_ctx(r, L, ctx);
    }

    ctx->entered_content_phase = 1;

    /*  {{{ new coroutine to handle request */
    co = ngx_http_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     "lua: failed to create new coroutine to handle request");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*  move code closure to new coroutine */
    lua_xmove(L, co, 1);

    /*  set closure's env table to new coroutine's globals table */
    ngx_http_lua_get_globals_table(co);
    lua_setfenv(co, -2);

    /* save nginx request in coroutine globals table */
    ngx_http_lua_set_req(co, r);

    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NGX_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    /* register request cleanup hooks */
    if (ctx->cleanup == NULL) {
        cln = ngx_http_cleanup_add(r, 0);
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln->handler = ngx_http_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }

    ctx->context = NGX_HTTP_LUA_CONTEXT_SSL_SIGN;

    rc = ngx_http_lua_run_thread(L, r, ctx, 0);

    if (rc == NGX_ERROR || rc >= NGX_OK) {
        /* do nothing */

    } else if (rc == NGX_AGAIN) {
        rc = ngx_http_lua_content_run_posted_threads(L, r, ctx, 0);

    } else if (rc == NGX_DONE) {
        rc = ngx_http_lua_content_run_posted_threads(L, r, ctx, 1);

    } else {
        rc = NGX_OK;
    }

    ngx_http_lua_finalize_request(r, rc);
    return rc;
}


#ifndef NGX_LUA_NO_FFI_API

int
ngx_http_lua_ffi_ssl_get_sign_type(ngx_http_request_t *r,
    int *type, char **err)
{
    ngx_ssl_conn_t          *ssl_conn;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    *type = ssl_conn->key_ex.type;

    return NGX_OK;
}


int
ngx_http_lua_ffi_ssl_get_sign_nid(ngx_http_request_t *r,
    int *nid, char **err)
{
    ngx_ssl_conn_t          *ssl_conn;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    *nid = ssl_conn->key_ex.nid;

    return NGX_OK;
}


int
ngx_http_lua_ffi_ssl_get_sign_data(ngx_http_request_t *r,
    unsigned char **data, size_t *datalen, char **err)
{
    ngx_ssl_conn_t          *ssl_conn;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    *data = ssl_conn->key_ex.from;

    if (*data) {
        *datalen = ssl_conn->key_ex.flen;
        return NGX_OK;
    }

    return NGX_DECLINED;
}


int
ngx_http_lua_ffi_ssl_set_sign_data(ngx_http_request_t *r,
    const unsigned char *data, size_t len, char **err)
{
    ngx_ssl_conn_t          *ssl_conn;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    ngx_memcpy(ssl_conn->key_ex.to, data, len);
    ssl_conn->key_ex.tlen = len;

    return NGX_OK;
}


int
ngx_http_lua_ffi_rsa_sign_by_key(int digest_nid, const unsigned char *key,
        size_t key_len, const u_char *data, size_t data_len,
        u_char *sign, char **err)
{
    BIO               *bio = NULL;
    EVP_PKEY          *pkey = NULL;
    RSA               *rsa;
    int               sign_len;

    bio = BIO_new_mem_buf((char *) key, key_len);
    if (bio == NULL) {
        *err = "BIO_new_mem_buf() failed";
        return NGX_ERROR;
    }

    pkey = d2i_PrivateKey_bio(bio, NULL);
    if (pkey == NULL) {
        BIO_free(bio);
        *err = "d2i_PrivateKey_bio() failed";
        return NGX_ERROR;
    }

    BIO_free(bio);

    rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        EVP_PKEY_free(pkey);
        *err = "EVP_PKEY_get1_RSA failed";
        return NGX_ERROR;
    }

    EVP_PKEY_free(pkey);

    if (RSA_sign(digest_nid, data, data_len, sign, &sign_len, rsa) != 1) {
        RSA_free(rsa);
        *err = "RSA_sign failed";
        return NGX_ERROR;
    }

    RSA_free(rsa);

    return sign_len;
}


int
ngx_http_lua_ffi_ecdsa_sign_by_key(int digest_nid, const unsigned char *key,
        size_t key_len, const u_char *data, size_t data_len,
        u_char *sign, char **err)
{
    BIO               *bio = NULL;
    EVP_PKEY          *pkey = NULL;
    EC_KEY            *ec_key;
    int               sign_len;

    bio = BIO_new_mem_buf((char *) key, key_len);
    if (bio == NULL) {
        *err = "BIO_new_mem_buf() failed";
        return NGX_ERROR;
    }

    pkey = d2i_PrivateKey_bio(bio, NULL);
    if (pkey == NULL) {
        BIO_free(bio);
        *err = "d2i_PrivateKey_bio() failed";
        return NGX_ERROR;
    }

    BIO_free(bio);

    ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (ec_key == NULL) {
        EVP_PKEY_free(pkey);
        *err = "EVP_PKEY_get1_EC_KEY failed";
        return NGX_ERROR;
    }

    EVP_PKEY_free(pkey);

    if (ECDSA_sign(digest_nid, data, data_len, sign, &sign_len, ec_key) != 1) {
        EC_KEY_free(ec_key);
        *err = "ECDSA_sign failed";
        return NGX_ERROR;
    }

    EC_KEY_free(ec_key);

    return sign_len;
}


#endif  /* NGX_LUA_NO_FFI_API */


#endif /* NGX_HTTP_SSL */

/**
 *    Copyright(c) 2017 rryqszq4
 *
 *
 */

#include <sqlite3.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_conf_file.h>
#include <nginx.h>

#include <string.h>

#include "ngx_http_sqlite_module.h"
#define SQLITE_ERR_OK "success"
#define SQLITE_ERR_NO_DATA "empty_query_sql"
#define SQLITE_ERR_BODY_TO_LARGE "post_too_large"

sqlite3 *sqlite_db = NULL;

static ngx_int_t ngx_http_sqlite_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_sqlite_handler_init(ngx_http_core_main_conf_t *cmcf, ngx_http_sqlite_main_conf_t *smcf);

static void *ngx_http_sqlite_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_sqlite_init_main_conf(ngx_conf_t *cf, void *conf);

static void *ngx_http_sqlite_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_sqlite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_sqlite_init_worker(ngx_cycle_t *cycle);
static void ngx_http_sqlite_exit_worker(ngx_cycle_t *cycle);

// directive
char *ngx_http_sqlite_database(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_sqlite_pragma(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_sqlite_content_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// handler
ngx_int_t ngx_http_sqlite_content_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_sqlite_content_query_handler(ngx_http_request_t *r);
int ngx_http_sqlite_sql_result(void *arg, int n_column, char **column_value, char **column_name);

void ngx_http_sqlite_echo(ngx_http_request_t *r, const char *data, size_t len);
static void ngx_http_sqlite_query_callback_handler(ngx_http_request_t *r);
static int json_printer(ngx_http_request_t *r, sqlite3_stmt *stmt);
static char * str_lower_left(char *dst,const char *src, int n);

static ngx_command_t ngx_http_sqlite_commands[] = {

    {ngx_string("sqlite_database"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_http_sqlite_database,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("sqlite_pragma"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_http_sqlite_pragma,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("sqlite_query"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
     ngx_http_sqlite_content_phase,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     ngx_http_sqlite_content_query_handler},

    ngx_null_command

};

static ngx_http_module_t ngx_http_sqlite_module_ctx = {
    NULL,                 /* preconfiguration */
    ngx_http_sqlite_init, /* postconfiguration */

    ngx_http_sqlite_create_main_conf, /* create main configuration */
    ngx_http_sqlite_init_main_conf,   /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_sqlite_create_loc_conf, /* create location configuration */
    ngx_http_sqlite_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_sqlite_module = {
    NGX_MODULE_V1,
    &ngx_http_sqlite_module_ctx, /* module context */
    ngx_http_sqlite_commands,    /* module directives */
    NGX_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    ngx_http_sqlite_init_worker, /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    ngx_http_sqlite_exit_worker, /* exit process */
    NULL,                        /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t
ngx_http_sqlite_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_sqlite_main_conf_t *smcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_sqlite_module);

    ngx_sqlite_request = NULL;

    if (ngx_http_sqlite_handler_init(cmcf, smcf) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_sqlite_handler_init(ngx_http_core_main_conf_t *cmcf, ngx_http_sqlite_main_conf_t *smcf)
{
    ngx_int_t i;
    ngx_http_handler_pt *h;
    ngx_http_phases phase;
    ngx_http_phases phases[] = {
        NGX_HTTP_CONTENT_PHASE,
    };

    ngx_int_t phases_c;

    phases_c = sizeof(phases) / sizeof(ngx_http_phases);
    for (i = 0; i < phases_c; i++)
    {
        phase = phases[i];
        switch (phase)
        {
        case NGX_HTTP_CONTENT_PHASE:
            if (smcf->enabled_content_handler)
            {
                h = ngx_array_push(&cmcf->phases[phase].handlers);
                if (h == NULL)
                {
                    return NGX_ERROR;
                }
                *h = ngx_http_sqlite_content_handler;
            }
            break;
        default:
            break;
        }
    }

    return NGX_OK;
}

static void *
ngx_http_sqlite_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_sqlite_main_conf_t *smcf;

    smcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sqlite_main_conf_t));
    if (smcf == NULL)
    {
        return NULL;
    }

    smcf->sqlite_database.len = 0;

    return smcf;
}

static char *
ngx_http_sqlite_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}

static void *
ngx_http_sqlite_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_sqlite_loc_conf_t *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sqlite_loc_conf_t));
    if (slcf == NULL)
    {
        return NGX_CONF_ERROR;
    }

    slcf->sqlite_query = NGX_CONF_UNSET_PTR;

    return slcf;
}

static char *
ngx_http_sqlite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    // ngx_http_core_loc_conf_t *clcf;
    // clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    ngx_http_sqlite_loc_conf_t *prev = parent;
    ngx_http_sqlite_loc_conf_t *conf = child;

    prev->sqlite_query = conf->sqlite_query;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_sqlite_init_worker(ngx_cycle_t *cycle)
{
    ngx_http_sqlite_main_conf_t *smcf;

    smcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_sqlite_module);

    if (smcf->sqlite_database.len != 0)
    {
        sqlite3_open((char *)smcf->sqlite_database.data, &sqlite_db);
        ngx_http_sqlite_pragma_list *current = smcf->pragma_list;
        while (current)
        {
            sqlite3_stmt *stmt;
            sqlite3_prepare_v2(
                sqlite_db,
                (char *)(current->pragma.data),
                current->pragma.len,
                &stmt,
                NULL);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            current = current->next;
        }
    }

    //sqlite3_open("/root/source/lnmp1.1-full/nginx-1.6.0/test.db", &sqlite_db);

    return NGX_OK;
}

static void
ngx_http_sqlite_exit_worker(ngx_cycle_t *cycle)
{
    sqlite3_close(sqlite_db);
}

char *
ngx_http_sqlite_database(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sqlite_main_conf_t *smcf = conf;
    ngx_str_t *value;

    if (smcf->sqlite_database.len != 0)
    {
        return "is duplicated";
    }

    value = cf->args->elts;

    smcf->sqlite_database.len = value[1].len;
    smcf->sqlite_database.data = value[1].data;

    return NGX_CONF_OK;
}

char *
ngx_http_sqlite_pragma(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sqlite_main_conf_t *smcf = conf;
    ngx_str_t *value;
    value = cf->args->elts;
    ngx_http_sqlite_pragma_list *current;
    current = ngx_pcalloc(cf->pool, sizeof(ngx_http_sqlite_pragma_list));
    if (current == NULL)
    {
        return NULL;
    }
    if (smcf->pragma_tail)
    {
        smcf->pragma_tail->next = current;
    }
    smcf->pragma_tail = current;

    if (smcf->pragma_list == NULL)
    {
        smcf->pragma_list = current;
    }
    current->pragma.len = value[1].len;
    current->pragma.data = value[1].data;
    return NGX_CONF_OK;
}

char *
ngx_http_sqlite_content_phase(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sqlite_main_conf_t *smcf;
    ngx_http_sqlite_loc_conf_t *slcf;
    ngx_http_sqlite_query_t *sqlite_query;
    ngx_str_t *value;
    size_t len;

    if (cmd->post == NULL)
    {
        return NGX_CONF_ERROR;
    }

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_sqlite_module);
    slcf = conf;

    if (slcf->content_handler != NULL)
    {
        return "is duplicated";
    }

    value = cf->args->elts;

    sqlite_query = ngx_pcalloc(cf->pool, sizeof(*sqlite_query));
    if (sqlite_query == NULL)
    {
        return NGX_CONF_UNSET_PTR;
    }

    len = ngx_strlen((&value[1])->data);
    sqlite_query->sql = ngx_pcalloc(cf->pool, len + 1);
    if (sqlite_query->sql == NULL)
    {
        return NGX_CONF_UNSET_PTR;
    }

    ngx_cpystrn((u_char *)sqlite_query->sql, (&value[1])->data, len + 1);

    slcf->sqlite_query = sqlite_query;
    slcf->content_handler = cmd->post;
    smcf->enabled_content_handler = 1;

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_sqlite_content_handler(ngx_http_request_t *r)
{
    ngx_http_sqlite_loc_conf_t *slcf;
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sqlite_module);
    if (slcf->content_handler == NULL)
    {
        return NGX_DECLINED;
    }
    return slcf->content_handler(r);
}

int ngx_http_sqlite_sql_result(void *arg, int n_column, char **column_value, char **column_name)
{
    /*int i = 0;

    ngx_buf_t *b;
    ngx_http_sqlite_rputs_chain_list_t *chain;
    ngx_http_sqlite_ctx_t *ctx;
    ngx_http_request_t *r;
    u_char *u_str;
    ngx_str_t ns;

    r = ngx_sqlite_request;
    ctx = ngx_http_get_module_ctx(r, ngx_http_sqlite_module);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "123");

    //int param = *((int *)arg);

    //printf("enter callback ---> param = %d, n_column = %d\n", param, n_column);

    if (ctx->rputs_chain == NULL){
        chain = ngx_pcalloc(r->pool, sizeof(ngx_http_sqlite_rputs_chain_list_t));
        chain->out = ngx_alloc_chain_link(r->pool);
        chain->last = &chain->out;
    }else {
        chain = ctx->rputs_chain;
        (*chain->last)->next = ngx_alloc_chain_link(r->pool);
        chain->last = &(*chain->last)->next;
    }

    ngx_int_t rc;

    for(i = 0; i < n_column; i++) {
        ns.len = strlen(column_name[i]);
        ns.data = (u_char *) column_name[i];

        b = ngx_calloc_buf(r->pool);
        (*chain->last)->buf = b;
        (*chain->last)->next = NULL;

        u_str = ngx_pstrdup(r->pool, &ns);
        //u_str[ns.len] = '\0';
        (*chain->last)->buf->pos = u_str;
        (*chain->last)->buf->last = u_str + ns.len;
        (*chain->last)->buf->memory = 1;
        ctx->rputs_chain = chain;

        if (r->headers_out.content_length_n == -1){
            r->headers_out.content_length_n += ns.len + 1;
        }else {
            r->headers_out.content_length_n += ns.len;
        }
    }

    for(i = 0; i < n_column; i++) {
        ns.len = strlen(column_value[i]);
        ns.data = (u_char *) column_value[i];

        b = ngx_calloc_buf(r->pool);
        (*chain->last)->buf = b;
        (*chain->last)->next = NULL;

        u_str = ngx_pstrdup(r->pool, &ns);
        //u_str[ns.len] = '\0';
        (*chain->last)->buf->pos = u_str;
        (*chain->last)->buf->last = u_str + ns.len;
        (*chain->last)->buf->memory = 1;
        ctx->rputs_chain = chain;

        if (r->headers_out.content_length_n == -1){
            r->headers_out.content_length_n += ns.len + 1;
        }else {
            r->headers_out.content_length_n += ns.len;
        }
    }

    if (!r->headers_out.status){
        r->headers_out.status = NGX_HTTP_OK;
    }

    if (r->method == NGX_HTTP_HEAD){
        rc = ngx_http_send_header(r);
        if (rc != NGX_OK){
            return rc;
        }
    }

    if (chain != NULL){
        (*chain->last)->buf->last_buf = 1;
    }

    rc = ngx_http_send_header(r);
    if (rc != NGX_OK){
        return rc;
    }

    ngx_http_output_filter(r, chain->out);

    ngx_http_set_ctx(r, NULL, ngx_http_sqlite_module);
      */
    return 0;
}

static void ngx_http_sqlite_query_callback_handler(ngx_http_request_t *r)
{
    int                          rc, nbufs;
    u_char                      *msg, *err_msg;
    size_t                       len, err_msg_size;
    ngx_chain_t                 *cl, *in;
    ngx_http_request_body_t     *body;
    ngx_http_sqlite_rputs_chain_list_t *chain = NULL;
    int result_code = 0;

    err_msg = NULL;
    err_msg_size = 0;

    /* get body */
    body = r->request_body;
    if (body == NULL || body->bufs == NULL ) {
        err_msg = (u_char *)SQLITE_ERR_NO_DATA;
        err_msg_size = sizeof(SQLITE_ERR_NO_DATA)-1;
        r->headers_out.status = NGX_HTTP_OK;
        goto end;
    }
    /* calc len and bufs */
    len = 0;
    nbufs = 0;
    in = body->bufs;
    for (cl = in; cl != NULL; cl = cl->next) {
        nbufs++;
        len += (size_t)(cl->buf->last - cl->buf->pos);
    }

    /* get msg */
    if (nbufs == 0) {
        err_msg = (u_char *)SQLITE_ERR_NO_DATA;
        err_msg_size = sizeof(SQLITE_ERR_NO_DATA)-1;
        r->headers_out.status = NGX_HTTP_OK;
        goto end;
    }

    if (nbufs == 1 && ngx_buf_in_memory(in->buf)) {
        msg = in->buf->pos;
        msg[len]='\0';
    } else {
        if ((msg = ngx_pnalloc(r->pool, len)) == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        for (cl = in; cl != NULL; cl = cl->next) {
            if (ngx_buf_in_memory(cl->buf)) {
                msg = ngx_copy(msg, cl->buf->pos, cl->buf->last - cl->buf->pos);
            } else {
                /* TODO: handle buf in file */
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "ngx_sqlite cannot handle in-file-post-buf");

                err_msg = (u_char *)SQLITE_ERR_BODY_TO_LARGE;
                err_msg_size = sizeof(SQLITE_ERR_BODY_TO_LARGE)-1;
                r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto end;
            }
        }
        msg -= len;
    }
    sqlite3_stmt *stmt;
    const char *rest = (const char *)msg;
    while (rest != 0 && ngx_strlen(rest) > 0)
    {
        result_code = sqlite3_prepare_v2(
            sqlite_db,
            rest,
            ngx_strlen(rest),
            &stmt,
            &rest);

        if (SQLITE_OK != result_code)
        {
            err_msg = (u_char *)sqlite3_errmsg(sqlite_db);
            err_msg_size = ngx_strlen(sqlite3_errmsg(sqlite_db));
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sqlite.err: %s,%d", sqlite3_errmsg(sqlite_db),result_code);
            sqlite3_finalize(stmt);
            break;
        }
        else
        {
            result_code = json_printer(r, stmt);
            sqlite3_finalize(stmt);
            if (result_code != SQLITE_OK && result_code != SQLITE_DONE)
            {
                // on error break
                sqlite3_stmt *stmt;
                const char *rollback_string = "rollback;";
                sqlite3_prepare_v2(
                    sqlite_db,
                    rollback_string,
                    strlen(rollback_string),
                    &stmt,
                    NULL);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                break;
            }
        }
        if ((result_code == SQLITE_OK || result_code == SQLITE_DONE) && r->headers_out.status == NGX_HTTP_OK)
        {
            r->headers_out.status = NGX_HTTP_OK;
        }
        else
        {
            r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        while (*rest == ' ' || *rest == '\n')
        {
            rest += 1;
        }
    }

end:
    if (err_msg != NULL) {
        ngx_http_sqlite_echo(r, "{\"code\":1,\"error\":\"post_", 24);
        ngx_http_sqlite_echo(r, (const char *)err_msg, err_msg_size);
        ngx_http_sqlite_echo(r, "\"}", 2);
    }
    ngx_http_sqlite_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_sqlite_module);
    chain = ctx->rputs_chain;

    if (!r->headers_out.status)
    {
        r->headers_out.status = NGX_HTTP_OK;
    }

    if (r->method == NGX_HTTP_HEAD)
    {
        rc = ngx_http_send_header(r);
        if (rc != NGX_OK)
        {
            return;
        }
    }

    if (chain != NULL)
    {
        (*chain->last)->buf->last_buf = 1;
    }

    rc = ngx_http_send_header(r);
    if (rc != NGX_OK)
    {
        return;
    }

    if (chain != NULL)
    {
        ngx_http_output_filter(r, chain->out);
    }

    ngx_http_set_ctx(r, NULL, ngx_http_sqlite_module);
    ngx_http_finalize_request(r, rc);
    return;
}
typedef int (*ngx_http_sqlite_result_printer_t)(ngx_http_request_t *, sqlite3_stmt *);

ngx_int_t
ngx_http_sqlite_content_query_core(ngx_http_request_t *r, ngx_http_sqlite_result_printer_t printer)
{
    ngx_http_sqlite_rputs_chain_list_t *chain = NULL;

    ngx_int_t rc;

    ngx_http_sqlite_loc_conf_t *slcf = ngx_http_get_module_loc_conf(r, ngx_http_sqlite_module);

    ngx_http_sqlite_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_sqlite_module);

    if (ctx == NULL)
    {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL)
        {
            return NGX_ERROR;
        }
    }

    ctx->request_body_more = 1;
    ngx_http_set_ctx(r, ctx, ngx_http_sqlite_module);

    ngx_sqlite_request = r;

    sqlite3_stmt *stmt;
    int result_code = 0;
    const char *rest = slcf->sqlite_query->sql;

    r->headers_out.status = NGX_HTTP_OK;
    if ( r->method & NGX_HTTP_POST ) {
        rc = ngx_http_read_client_request_body(r, ngx_http_sqlite_query_callback_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;
    }
    // parse query string
    char *buf = ngx_pcalloc(r->pool, r->args.len + 1);
    char **keys = NULL;
    char **values = NULL;
    int pair_count = 1;
    unsigned i = 0;
    u_char    *err_msg = NULL;
    size_t    err_msg_size = 0;
    if (buf != NULL)
    {
        ngx_memcpy(buf, r->args.data, r->args.len);
        // count for '&'
        for (i = 0; i < r->args.len; i++)
        {
            if (buf[i] == '&')
            {
                pair_count += 1;
            }
        }
        keys = ngx_pcalloc(r->pool, sizeof(char *) * pair_count);
        values = ngx_pcalloc(r->pool, sizeof(char *) * pair_count);
        if (keys != NULL && values != NULL)
        {
            int crn_key = 0;
            int crn_value = 0;
            keys[crn_key] = &buf[0];
            crn_key += 1;
            for (i = 0; i < r->args.len; i++)
            {
                if (buf[i] == '&')
                {
                    if (crn_value < crn_key)
                    {
                        values[crn_value] = &buf[i];
                        crn_value += 1;
                    }
                    keys[crn_key] = &buf[i + 1];
                    crn_key += 1;
                    buf[i] = '\0';
                }
                else if (buf[i] == '=')
                {
                    if (crn_value < crn_key)
                    {
                        values[crn_value] = &buf[i + 1];
                        crn_value += 1;
                        buf[i] = '\0';
                    }
                    else
                    {
                    }
                }
                else
                {
                }
            }
            if (crn_value < crn_key)
            {
                values[crn_value] = &buf[r->args.len];
            }
        }
        else
        {
            keys = NULL;
            values = NULL;
        }
    }
    // do the query
    while (rest != 0 && ngx_strlen(rest) > 0)
    {
        result_code = sqlite3_prepare_v2(
            sqlite_db,
            rest,
            ngx_strlen(rest),
            &stmt,
            &rest);

        if (SQLITE_OK != result_code)
        {
            err_msg = (u_char *)sqlite3_errmsg(sqlite_db);
            err_msg_size = ngx_strlen(sqlite3_errmsg(sqlite_db));
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sqlite.err: %s,%d",sqlite3_errmsg(sqlite_db),result_code);
            sqlite3_finalize(stmt);
            goto end;
        }
        else
        {
            if (buf != NULL && keys != NULL && values != NULL)
            {
                int para_count = sqlite3_bind_parameter_count(stmt);
                int para_index = 0;
                int key_count = 0;
                for (para_index = 0; para_index < para_count; para_index++)
                {
                    char const *name = sqlite3_bind_parameter_name(stmt, para_index + 1);
                    key_count = pair_count - 1;
                    for (; key_count > -1; key_count--)
                    {
                        if (strcmp(&name[1], keys[key_count]) == 0)
                        {
                            break;
                        }
                    }
                    if (key_count > -1)
                    {
                        sqlite3_bind_text(stmt, para_index + 1, values[key_count], -1, SQLITE_STATIC);
                    }
                    else
                    {
                        sqlite3_bind_null(stmt, para_index + 1);
                    }
                }
            }
            result_code = json_printer(r, stmt);
            sqlite3_finalize(stmt);
            if (result_code != SQLITE_OK && result_code != SQLITE_DONE)
            {
                // on error break
                sqlite3_stmt *stmt;
                const char *rollback_string = "rollback;";
                sqlite3_prepare_v2(
                    sqlite_db,
                    rollback_string,
                    strlen(rollback_string),
                    &stmt,
                    NULL);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
                goto end;
            }
        }
        if ((result_code == SQLITE_OK || result_code == SQLITE_DONE) && r->headers_out.status == NGX_HTTP_OK)
        {
            r->headers_out.status = NGX_HTTP_OK;
        }
        else
        {
            r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        while (*rest == ' ' || *rest == '\n')
        {
            rest += 1;
        }
    }
    ngx_pfree(r->pool, buf);
    ngx_pfree(r->pool, keys);
    ngx_pfree(r->pool, values);
    ctx = ngx_http_get_module_ctx(r, ngx_http_sqlite_module);
    chain = ctx->rputs_chain;

end:
    if (err_msg != NULL) {
        ngx_http_sqlite_echo(r, "{\"code\":1,\"error\":\"post_", 24);
        ngx_http_sqlite_echo(r, (const char *)err_msg, err_msg_size);
        ngx_http_sqlite_echo(r, "\"}", 2);
    }

    if (!r->headers_out.status)
    {
        r->headers_out.status = NGX_HTTP_OK;
    }

    if (r->method == NGX_HTTP_HEAD)
    {
        rc = ngx_http_send_header(r);
        if (rc != NGX_OK)
        {
            return rc;
        }
    }

    if (chain != NULL)
    {
        (*chain->last)->buf->last_buf = 1;
    }

    rc = ngx_http_send_header(r);
    if (rc != NGX_OK)
    {
        return rc;
    }

    if (chain != NULL)
    {
        ngx_http_output_filter(r, chain->out);
    }

    ngx_http_set_ctx(r, NULL, ngx_http_sqlite_module);

    return NGX_OK;
}

ngx_int_t
ngx_http_sqlite_content_query_handler(ngx_http_request_t *r)
{
    return ngx_http_sqlite_content_query_core(r, json_printer);
}
/*从字符串的左边截取n个字符*/
static char * str_lower_left(char *dst,const char *src, int n)
{
    char *q = dst;
    int len = strlen(src);
    if(n>len) n = len;
    /*p += (len-n);*/   /*从右边第n个字符开始*/
    while(n--) *(q++) = tolower(*(src++));
    *(q++)='\0'; /*有必要吗？很有必要*/
    return dst;
}
static int
json_printer(ngx_http_request_t *r, sqlite3_stmt *stmt)
{
    u_char  *err_msg = (u_char *)SQLITE_ERR_OK;
    size_t err_msg_size = sizeof(SQLITE_ERR_OK)-1;
    ngx_str_set(&(r->headers_out.content_type), "application/json");
    ngx_http_sqlite_echo(r, "{\"data\":[", 9);
    int result_code = 0;
    int num_of_columns = 0;
    result_code = sqlite3_step(stmt);
    const char *sql = sqlite3_sql(stmt);
    char opsql[7]={'\0'};
    str_lower_left(opsql,sql,6); 
    if( strcmp(opsql,"select")==0 ){
        num_of_columns = sqlite3_column_count(stmt);
        while (result_code == SQLITE_ROW)
        {
            ngx_http_sqlite_echo(r, "{", 1);
            int need_comma = 0;
            int i = 0;
            for (i = 0; i < num_of_columns; i++)
            {
                const unsigned char *result = sqlite3_column_text(stmt, i);
                if (result != NULL)
                {
                    if (need_comma)
                    {
                        ngx_http_sqlite_echo(r,  ",", 1);
                    }
                    need_comma = 1;
                    ngx_http_sqlite_echo(r, "\"", 1);
                    ngx_http_sqlite_echo(r, (char *)sqlite3_column_name(stmt, i), ngx_strlen(sqlite3_column_name(stmt, i)));
                    ngx_http_sqlite_echo(r, "\":\"", 3);
                    ngx_http_sqlite_echo(r, (char *)result, ngx_strlen(result));
                    ngx_http_sqlite_echo(r, "\"", 1);
                }
            }
            ngx_http_sqlite_echo(r, "}", 1);
            result_code = sqlite3_step(stmt);
            if (result_code == SQLITE_ROW)
            {
                ngx_http_sqlite_echo(r, ",", 1);
            }
        }
    }
    char rbuffer[50];
    int rlen = 0;
    if (result_code != SQLITE_OK && result_code != SQLITE_DONE)
    {
        err_msg = (u_char *)sqlite3_errmsg(sqlite_db);
        err_msg_size = ngx_strlen(sqlite3_errmsg(sqlite_db));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "sqlite.err: %s,%d",sqlite3_errmsg(sqlite_db),result_code);
    }else{
        if ( strcmp(opsql,"select")!=0 ){
            rlen = sprintf(rbuffer, "%d", sqlite3_changes(sqlite_db));
            ngx_http_sqlite_echo(r, rbuffer, rlen);
            if(strcmp(opsql,"insert")==0){
                ngx_http_sqlite_echo(r, ",",1);
                rlen = sprintf(rbuffer, "%Ld", sqlite3_last_insert_rowid(sqlite_db));
                ngx_http_sqlite_echo(r, rbuffer, rlen);
            }
        }
    }
    ngx_http_sqlite_echo(r, "],\"error\":\"",11);
    ngx_http_sqlite_echo(r, (const char *)err_msg, err_msg_size);
    ngx_http_sqlite_echo(r, "\",\"code\":",9);
    if( result_code == SQLITE_DONE ){
        result_code = SQLITE_OK;
    }
    rlen = sprintf(rbuffer, "%d", result_code);
    ngx_http_sqlite_echo(r, rbuffer, rlen);
    ngx_http_sqlite_echo(r, "}",1);
    return result_code;
}

void ngx_http_sqlite_echo(ngx_http_request_t *r, const char *data, size_t len)
{
    if (len == 0)
    {
        return;
    }
    ngx_buf_t *b;
    ngx_http_sqlite_rputs_chain_list_t *chain;
    ngx_http_sqlite_ctx_t *ctx;

    u_char *u_str;
    ngx_str_t ns;

    ctx = ngx_http_get_module_ctx(r, ngx_http_sqlite_module);

    ns.len = len;
    ns.data = (u_char *)data;

    if (ctx->rputs_chain == NULL)
    {
        chain = ngx_pcalloc(r->pool, sizeof(ngx_http_sqlite_rputs_chain_list_t));
        chain->out = ngx_alloc_chain_link(r->pool);
        chain->last = &chain->out;
    }
    else
    {
        chain = ctx->rputs_chain;
        (*chain->last)->next = ngx_alloc_chain_link(r->pool);
        chain->last = &(*chain->last)->next;
    }

    b = ngx_calloc_buf(r->pool);
    (*chain->last)->buf = b;
    (*chain->last)->next = NULL;

    u_str = ngx_pstrdup(r->pool, &ns);
    //u_str[ns.len] = '\0';
    (*chain->last)->buf->pos = u_str;
    (*chain->last)->buf->last = u_str + ns.len;
    (*chain->last)->buf->memory = 1;
    ctx->rputs_chain = chain;

    if (r->headers_out.content_length_n == -1)
    {
        r->headers_out.content_length_n += ns.len + 1;
    }
    else
    {
        r->headers_out.content_length_n += ns.len;
    }
}

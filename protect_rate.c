#include "protect_rate.h"

#include "http_config.h"
#include "http_log.h"
#include "apr_global_mutex.h"
#include "apr_shm.h"
#include "apr_strings.h"

#include <string.h>
#include <unistd.h>

#define PROTECT_RATE_SLOTS 16384
#define PROTECT_RATE_KEY_URI 1
#define PROTECT_RATE_KEY_URI_DYNAMIC 2
#define PROTECT_RATE_KEY_SITE 3

typedef struct {
    apr_uint64_t hash;
    apr_time_t window_start;
    apr_uint32_t count;
} protect_rate_entry;

typedef struct {
    protect_rate_entry uri[PROTECT_RATE_SLOTS];
    protect_rate_entry uri_dynamic[PROTECT_RATE_SLOTS];
    protect_rate_entry site[PROTECT_RATE_SLOTS];
} protect_rate_shared;

static apr_shm_t *protect_rate_shm;
static protect_rate_shared *protect_rate_data;
static apr_global_mutex_t *protect_rate_mutex;

static apr_uint64_t protect_rate_hash(const char *key)
{
    const unsigned char *p = (const unsigned char *)key;
    apr_uint64_t h = UINT64_C(1469598103934665603);

    while (*p) {
        h ^= *p++;
        h *= UINT64_C(1099511628211);
    }

    return h ? h : 1;
}

static int protect_rate_dynamic(request_rec *r)
{
    if (!r->handler) {
        return 0;
    }

    if (!strcmp(r->handler, "cgi-script") ||
        !strcmp(r->handler, "fcgid-script") ||
        !strcmp(r->handler, "proxy-server")) {
        return 1;
    }

    if (!strncmp(r->handler, "proxy:", 6)) {
        return 1;
    }

    if (r->filename && !strncmp(r->filename, "proxy:", 6)) {
        return 1;
    }

    return 0;
}

static int protect_rate_hit(protect_rate_entry *table,
                            apr_uint64_t hash,
                            apr_uint32_t limit,
                            apr_time_t interval)
{
    apr_uint32_t i;
    apr_uint32_t start = (apr_uint32_t)(hash % PROTECT_RATE_SLOTS);
    apr_time_t now = apr_time_now();

    for (i = 0; i < PROTECT_RATE_SLOTS; ++i) {
        protect_rate_entry *entry =
            &table[(start + i) % PROTECT_RATE_SLOTS];

        if (!entry->hash || entry->hash == hash) {
            if (!entry->hash ||
                now - entry->window_start >= interval) {
                entry->hash = hash;
                entry->window_start = now;
                entry->count = 1;
                return 0;
            }

            if (entry->count >= limit) {
                return 1;
            }

            ++entry->count;
            return 0;
        }
    }

    /* Table full: fail open rather than reject unrelated traffic. */
    return 0;
}

static const char *protect_rate_key_uri(request_rec *r, apr_pool_t *p)
{
    const char *ip = r->useragent_ip ? r->useragent_ip : "";
    const char *host = r->server->server_hostname ?
                       r->server->server_hostname : "";
    const char *uri = r->uri ? r->uri : "";

    return apr_pstrcat(p, "U|", host, "|", ip, "|", uri, NULL);
}

static const char *protect_rate_key_site(request_rec *r, apr_pool_t *p)
{
    const char *ip = r->useragent_ip ? r->useragent_ip : "";
    const char *host = r->server->server_hostname ?
                       r->server->server_hostname : "";

    return apr_pstrcat(p, "S|", host, "|", ip, NULL);
}

int protect_rate_check(request_rec *r, const protect_rate_config *cfg,
                       int *limited)
{
    const char *key;
    apr_status_t rv;

    if (!r || !cfg || !limited || !protect_rate_data ||
        !protect_rate_mutex || !r->connection ||
        !r->useragent_ip || !ap_is_initial_req(r)) {
        return DECLINED;
    }

    *limited = 0;

    if (!cfg->uri_count && !cfg->uri_dynamic_count && !cfg->site_count) {
        return DECLINED;
    }

    rv = apr_global_mutex_lock(protect_rate_mutex);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(10003)
                      "mod_protect: unable to lock rate-limit table");
        return DECLINED;
    }

    if (cfg->site_count && cfg->site_interval > 0) {
        key = protect_rate_key_site(r, r->pool);
        if (protect_rate_hit(protect_rate_data->site,
                             protect_rate_hash(key),
                             (apr_uint32_t)cfg->site_count,
                             apr_time_from_sec(cfg->site_interval))) {
            *limited = 1;
        }
    }

    if (!*limited && cfg->uri_count && cfg->uri_interval > 0) {
        key = protect_rate_key_uri(r, r->pool);
        if (protect_rate_hit(protect_rate_data->uri,
                             protect_rate_hash(key),
                             (apr_uint32_t)cfg->uri_count,
                             apr_time_from_sec(cfg->uri_interval))) {
            *limited = 1;
        }
    }

    if (!*limited && cfg->uri_dynamic_count &&
        cfg->uri_dynamic_interval > 0 && protect_rate_dynamic(r)) {
        key = protect_rate_key_uri(r, r->pool);
        key = apr_pstrcat(r->pool, "D|", key, NULL);
        if (protect_rate_hit(protect_rate_data->uri_dynamic,
                             protect_rate_hash(key),
                             (apr_uint32_t)cfg->uri_dynamic_count,
                             apr_time_from_sec(cfg->uri_dynamic_interval))) {
            *limited = 1;
        }
    }

    apr_global_mutex_unlock(protect_rate_mutex);

    return OK;
}

int protect_rate_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    const char *shm_file;
    const char *lock_file;
    apr_status_t rv;

    (void)plog;
    (void)ptemp;

    shm_file = ap_server_root_relative(pconf, "logs/protect-rates.shm");
    lock_file = ap_server_root_relative(pconf, "logs/protect-rates.lock");

    unlink(shm_file);
    unlink(lock_file);

    rv = apr_global_mutex_create(&protect_rate_mutex, lock_file,
                                 APR_LOCK_DEFAULT, pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(10004)
                     "mod_protect: unable to create rate-limit mutex");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = apr_shm_create(&protect_rate_shm, sizeof(protect_rate_shared),
                        shm_file, pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s, APLOGNO(10005)
                     "mod_protect: unable to create rate-limit shared memory");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    protect_rate_data = apr_shm_baseaddr_get(protect_rate_shm);
    memset(protect_rate_data, 0, sizeof(*protect_rate_data));

    return OK;
}

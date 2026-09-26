#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"
#include "apr_file_io.h"
#include "apr_strings.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "protect_scoreboard.h"
#include "protect_rate.h"

module AP_MODULE_DECLARE_DATA protect_module;

typedef struct {
    long max_concurrent_ip;
    long max_concurrent_vhost;
    protect_rate_config rate;
    const char *protect_log;
    apr_os_file_t protect_log_fd;
} protect_config;

static void *protect_create_server_config(apr_pool_t *p, server_rec *s)
{
    protect_config *cfg = apr_pcalloc(p, sizeof(*cfg));
    (void)s;
    cfg->max_concurrent_ip = 0;
    cfg->max_concurrent_vhost = 0;
    cfg->rate.uri_count = 0;
    cfg->rate.uri_interval = 0;
    cfg->rate.uri_dynamic_count = 0;
    cfg->rate.uri_dynamic_interval = 0;
    cfg->rate.site_count = 0;
    cfg->rate.site_interval = 0;
    cfg->protect_log = NULL;
    cfg->protect_log_fd = (apr_os_file_t)-1;
    return cfg;
}

static void *protect_merge_server_config(apr_pool_t *p, void *basev, void *overv)
{
    protect_config *base = (protect_config *)basev;
    protect_config *over = (protect_config *)overv;
    protect_config *cfg = apr_pcalloc(p, sizeof(*cfg));

    cfg->max_concurrent_ip = over->max_concurrent_ip;
    cfg->max_concurrent_vhost = over->max_concurrent_vhost;
    cfg->rate = over->rate;

    cfg->protect_log = over->protect_log ?
        over->protect_log : base->protect_log;
    cfg->protect_log_fd = over->protect_log_fd != (apr_os_file_t)-1 ?
        over->protect_log_fd : base->protect_log_fd;

    return cfg;
}

static const char *protect_set_limit(cmd_parms *cmd, void *dummy,
                                     const char *arg)
{
    protect_config *cfg = ap_get_module_config(cmd->server->module_config,
                                               &protect_module);
    char *end;
    long value;

    (void)dummy;

    value = strtol(arg, &end, 10);
    if (*arg == '\0' || *end != '\0' || value < 0) {
        return "mod_protect: limit must be a non-negative integer";
    }

    if (!strcmp(cmd->cmd->name, "ProtectMaxConcurrentPerIP")) {
        cfg->max_concurrent_ip = value;
    }
    else if (!strcmp(cmd->cmd->name, "ProtectMaxConcurrentPerVHost")) {
        cfg->max_concurrent_vhost = value;
    }

    return NULL;
}

static const char *protect_set_rate(cmd_parms *cmd, void *dummy,
                                    const char *arg)
{
    protect_config *cfg = ap_get_module_config(cmd->server->module_config,
                                               &protect_module);
    char *end;
    long value;

    (void)dummy;

    value = strtol(arg, &end, 10);
    if (*arg == '\0' || *end != '\0' || value < 0) {
        return "mod_protect: rate value must be a non-negative integer";
    }

    if (!strcmp(cmd->cmd->name, "ProtectURICount"))
        cfg->rate.uri_count = value;
    else if (!strcmp(cmd->cmd->name, "ProtectURIInterval"))
        cfg->rate.uri_interval = value;
    else if (!strcmp(cmd->cmd->name, "ProtectURIDynamicCount"))
        cfg->rate.uri_dynamic_count = value;
    else if (!strcmp(cmd->cmd->name, "ProtectURIDynamicInterval"))
        cfg->rate.uri_dynamic_interval = value;
    else if (!strcmp(cmd->cmd->name, "ProtectSiteCount"))
        cfg->rate.site_count = value;
    else if (!strcmp(cmd->cmd->name, "ProtectSiteInterval"))
        cfg->rate.site_interval = value;

    return NULL;
}

static void protect_log_event(request_rec *r, const char *type,
                              const char *message)
{
    protect_config *cfg;
    char *line;
    const char *p;
    size_t len;
    char timestamp[APR_CTIME_LEN];

    cfg = ap_get_module_config(r->server->module_config, &protect_module);
    if (cfg->protect_log_fd == (apr_os_file_t)-1) {
        return;
    }

    apr_ctime(timestamp, r->request_time);
    timestamp[strlen(timestamp) - 1] = '\0';
    line = apr_psprintf(r->pool, "[%s] [%s] %s\n", timestamp, type, message);
    p = line;
    len = strlen(line);

    while (len > 0) {
        ssize_t n = write(cfg->protect_log_fd, p, len);
        if (n > 0) {
            p += n;
            len -= (size_t)n;
        }
        else if (n < 0 && errno == EINTR) {
            continue;
        }
        else {
            break;
        }
    }
}

static int protect_fixups(request_rec *r)
{
    protect_config *cfg;
    protect_scoreboard_counts counts;
    int rv;
    int rate_limited = 0;
    const char *rate_reason = NULL;
    unsigned long rate_count = 0;
    long rate_limit = 0;

    if (!r->connection || !r->useragent_ip ||
        !ap_is_initial_req(r)) {
        return DECLINED;
    }

    cfg = ap_get_module_config(r->server->module_config, &protect_module);

    if (cfg->max_concurrent_ip || cfg->max_concurrent_vhost) {
        rv = protect_scoreboard_count(r, &counts);
        if (rv != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10001)
                          "mod_protect: scoreboard unavailable");
            return DECLINED;
        }

        if ((cfg->max_concurrent_ip &&
             counts.ip > (unsigned long)cfg->max_concurrent_ip) ||
            (cfg->max_concurrent_vhost &&
             counts.vhost > (unsigned long)cfg->max_concurrent_vhost)) {

            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, APLOGNO(10002)
                          "mod_protect: concurrent request limit exceeded: "
                          "ip=%s vhost=%s ip=%lu vhost=%lu",
                          r->useragent_ip,
                          r->server->server_hostname ?
                              r->server->server_hostname : "-",
                          counts.ip, counts.vhost);

            {
                char *message = apr_psprintf(r->pool,
                    "ip=%s vhost=%s ip=%lu/%ld vhost=%lu/%ld reason=%s uri=%s",
                    r->useragent_ip,
                    r->server->server_hostname ?
                        r->server->server_hostname : "-",
                    counts.ip, cfg->max_concurrent_ip, counts.vhost, cfg->max_concurrent_vhost, ((cfg->max_concurrent_ip && counts.ip > (unsigned long)cfg->max_concurrent_ip) && (cfg->max_concurrent_vhost && counts.vhost > (unsigned long)cfg->max_concurrent_vhost)) ? "ip,vhost" : (cfg->max_concurrent_ip && counts.ip > (unsigned long)cfg->max_concurrent_ip) ? "ip" : "vhost", r->uri ? r->uri : "-");
                protect_log_event(r, "concurrent", message);
            }

            return HTTP_TOO_MANY_REQUESTS;
        }
    }

    if (cfg->rate.uri_count || cfg->rate.uri_dynamic_count ||
        cfg->rate.site_count) {
        rv = protect_rate_check(r, &cfg->rate, &rate_limited, &rate_reason, &rate_count, &rate_limit);
        if (rv == OK && rate_limited) {
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, APLOGNO(10006)
                          "mod_protect: request rate limit exceeded: "
                          "ip=%s uri=%s",
                          r->useragent_ip,
                          r->uri ? r->uri : "-");

            {
                char *message = apr_psprintf(r->pool,
                    "ip=%s vhost=%s uri=%s count=%lu/%ld reason=%s",
                    r->useragent_ip,
                    r->server->server_hostname ?
                        r->server->server_hostname : "-",
                    r->uri ? r->uri : "-", rate_count, rate_limit, rate_reason ? rate_reason : "-");
                protect_log_event(r, "rate", message);
            }
            return HTTP_TOO_MANY_REQUESTS;
        }
    }

    return DECLINED;
}

static const char *protect_set_log(cmd_parms *cmd, void *dummy,
                                   const char *arg)
{
    protect_config *cfg = ap_get_module_config(cmd->server->module_config,
                                               &protect_module);
    apr_file_t *file;
    apr_status_t rv;
    apr_os_file_t fd;

    (void)dummy;

    cfg->protect_log = arg;

    rv = apr_file_open(&file, arg,
                       APR_WRITE | APR_APPEND | APR_CREATE | APR_BINARY,
                       APR_OS_DEFAULT, cmd->pool);
    if (rv != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "mod_protect: unable to open ProtectLog: %s",
                            arg);
    }

    rv = apr_os_file_get(&fd, file);
    if (rv != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "mod_protect: unable to get ProtectLog fd: %s",
                            arg);
    }

    /*
     * The APR file is owned by cmd->pool and will be closed when that
     * pool is destroyed. Keep an independent descriptor for use after
     * configuration parsing and by forked Apache children.
     */
    {
        int dupfd = dup(fd);
        if (dupfd == -1) {
            return apr_psprintf(cmd->pool,
                                "mod_protect: unable to duplicate ProtectLog fd: %s",
                                arg);
        }
        cfg->protect_log_fd = (apr_os_file_t)dupfd;
    }

    return NULL;
}

static const command_rec protect_cmds[] = {
    AP_INIT_TAKE1("ProtectLog", protect_set_log, NULL,
                  RSRC_CONF,
                  "Additional log file for requests rejected by mod_protect"),
    AP_INIT_TAKE1("ProtectMaxConcurrentPerIP", protect_set_limit, NULL,
                  RSRC_CONF,
                  "Maximum concurrent requests per client IP"),
    AP_INIT_TAKE1("ProtectMaxConcurrentPerVHost", protect_set_limit, NULL,
                  RSRC_CONF,
                  "Maximum concurrent requests per virtual host"),
    AP_INIT_TAKE1("ProtectURICount", protect_set_rate, NULL,
                  RSRC_CONF,
                  "Maximum requests per client IP to one URI per interval"),
    AP_INIT_TAKE1("ProtectURIInterval", protect_set_rate, NULL,
                  RSRC_CONF,
                  "URI request-rate interval in seconds"),
    AP_INIT_TAKE1("ProtectURIDynamicCount", protect_set_rate, NULL,
                  RSRC_CONF,
                  "Maximum dynamic requests per client IP to one URI per interval"),
    AP_INIT_TAKE1("ProtectURIDynamicInterval", protect_set_rate, NULL,
                  RSRC_CONF,
                  "Dynamic URI request-rate interval in seconds"),
    AP_INIT_TAKE1("ProtectSiteCount", protect_set_rate, NULL,
                  RSRC_CONF,
                  "Maximum requests per client IP to one virtual host per interval"),
    AP_INIT_TAKE1("ProtectSiteInterval", protect_set_rate, NULL,
                  RSRC_CONF,
                  "Site request-rate interval in seconds"),
    { NULL }
};

static int protect_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *s)
{
    server_rec *srv;

    (void)pconf;
    (void)plog;
    (void)ptemp;

    for (srv = s; srv; srv = srv->next) {
        protect_config *cfg =
            ap_get_module_config(srv->module_config, &protect_module);

        if (cfg->max_concurrent_ip || cfg->max_concurrent_vhost) {
            if (!ap_extended_status) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, srv, APLOGNO(10008)
                             "mod_protect: ExtendedStatus is disabled; "
                             "concurrent request limits may not work");
            }
            break;
        }
    }

    return OK;
}

static void protect_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(protect_rate_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(protect_post_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_fixups(protect_fixups, NULL, NULL, APR_HOOK_LAST);
    (void)p;
}

module AP_MODULE_DECLARE_DATA protect_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    protect_create_server_config,
    protect_merge_server_config,
    protect_cmds,
    protect_register_hooks
};

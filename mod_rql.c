#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"

#include <stdlib.h>
#include <string.h>

#include "rql_scoreboard.h"

module AP_MODULE_DECLARE_DATA rql_module;

typedef struct {
    long max_active;
    long max_active_ip;
    long max_active_vhost;
    long max_active_ip_vhost;
} rql_config;

static void *rql_create_server_config(apr_pool_t *p, server_rec *s)
{
    rql_config *cfg = apr_pcalloc(p, sizeof(*cfg));

    (void)s;

    cfg->max_active = 0;
    cfg->max_active_ip = 0;
    cfg->max_active_vhost = 0;
    cfg->max_active_ip_vhost = 0;

    return cfg;
}

static const char *rql_set_limit(cmd_parms *cmd, void *dummy,
                                 const char *arg)
{
    rql_config *cfg = ap_get_module_config(cmd->server->module_config,
                                           &rql_module);
    char *end;
    long value;

    (void)dummy;

    value = strtol(arg, &end, 10);
    if (*arg == '\0' || *end != '\0' || value < 0) {
        return "mod_rql: limit must be a non-negative integer";
    }

    if (!strcmp(cmd->cmd->name, "RQLMaxActive")) {
        cfg->max_active = value;
    }
    else if (!strcmp(cmd->cmd->name, "RQLMaxActivePerIP")) {
        cfg->max_active_ip = value;
    }
    else if (!strcmp(cmd->cmd->name, "RQLMaxActivePerVHost")) {
        cfg->max_active_vhost = value;
    }
    else if (!strcmp(cmd->cmd->name, "RQLMaxActivePerIPAndVHost")) {
        cfg->max_active_ip_vhost = value;
    }

    return NULL;
}

static int rql_fixups(request_rec *r)
{
    rql_config *cfg;
    rql_scoreboard_counts counts;
    int rv;

    if (!r->connection || !r->connection->client_ip) {
        return DECLINED;
    }

    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    cfg = ap_get_module_config(r->server->module_config, &rql_module);

    if (!cfg->max_active && !cfg->max_active_ip &&
        !cfg->max_active_vhost && !cfg->max_active_ip_vhost) {
        return DECLINED;
    }

    rv = rql_scoreboard_count(r, &counts);
    if (rv != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10001)
                      "mod_rql: scoreboard unavailable");
        return DECLINED;
    }

    if ((cfg->max_active && counts.global > (unsigned long)cfg->max_active) ||
        (cfg->max_active_ip && counts.ip > (unsigned long)cfg->max_active_ip) ||
        (cfg->max_active_vhost &&
         counts.vhost > (unsigned long)cfg->max_active_vhost) ||
        (cfg->max_active_ip_vhost &&
         counts.ip_vhost > (unsigned long)cfg->max_active_ip_vhost)) {

        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, APLOGNO(10002)
                      "mod_rql: request limit exceeded: ip=%s vhost=%s "
                      "global=%lu ip=%lu vhost=%lu ip_vhost=%lu",
                      r->connection->client_ip,
                      r->server->server_hostname ?
                          r->server->server_hostname : "-",
                      counts.global, counts.ip, counts.vhost,
                      counts.ip_vhost);

        return HTTP_TOO_MANY_REQUESTS;
    }

    return DECLINED;
}

static const command_rec rql_cmds[] = {
    AP_INIT_TAKE1("RQLMaxActive", rql_set_limit, NULL, RSRC_CONF,
                  "Maximum concurrent active requests globally"),
    AP_INIT_TAKE1("RQLMaxActivePerIP", rql_set_limit, NULL, RSRC_CONF,
                  "Maximum concurrent active requests per client IP"),
    AP_INIT_TAKE1("RQLMaxActivePerVHost", rql_set_limit, NULL, RSRC_CONF,
                  "Maximum concurrent active requests per virtual host"),
    AP_INIT_TAKE1("RQLMaxActivePerIPAndVHost", rql_set_limit, NULL, RSRC_CONF,
                  "Maximum concurrent active requests per client IP and vhost"),
    { NULL }
};

static void rql_register_hooks(apr_pool_t *p)
{
    (void)p;
    ap_hook_fixups(rql_fixups, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA rql_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    rql_create_server_config,
    NULL,
    rql_cmds,
    rql_register_hooks
};

#include "protect_scoreboard.h"

#include <stdio.h>
#include <string.h>

static int protect_scoreboard_request_active(unsigned char status)
{
    switch (status) {
    case SERVER_BUSY_READ:
    case SERVER_BUSY_WRITE:
    case SERVER_BUSY_DNS:
        return 1;
    default:
        return 0;
    }
}

int protect_scoreboard_count(request_rec *r, protect_scoreboard_counts *counts)
{
    global_score *global;
    int i, j;

    if (!counts || !r) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    memset(counts, 0, sizeof(*counts));

    if (!ap_exists_scoreboard_image()) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    global = ap_get_scoreboard_global();
    if (!global) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    for (i = 0; i < global->server_limit; ++i) {
        for (j = 0; j < global->thread_limit; ++j) {
            worker_score ws;

            ap_copy_scoreboard_worker(&ws, i, j);

            if (!protect_scoreboard_request_active(ws.status)) {
                continue;
            }

            ++counts->global;

            if (r->connection && r->connection->client_ip &&
                ws.client64[0] &&
                strcmp(r->connection->client_ip, ws.client64) == 0) {
                ++counts->ip;
            }

            if (r->server && r->server->server_hostname &&
                r->connection && r->connection->local_addr &&
                ws.vhost[0]) {
                char vhost[sizeof(ws.vhost)];

                snprintf(vhost, sizeof(vhost), "%s:%d",
                         r->server->server_hostname,
                         r->connection->local_addr->port);

                if (strcmp(vhost, ws.vhost) == 0) {
                    ++counts->vhost;
                }
            }
        }
    }

    return OK;
}

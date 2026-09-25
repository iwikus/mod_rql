#ifndef MOD_PROTECT_SCOREBOARD_H
#define MOD_PROTECT_SCOREBOARD_H

#include "httpd.h"
#include "scoreboard.h"

typedef struct {
    unsigned long global;
    unsigned long ip;
    unsigned long vhost;
} protect_scoreboard_counts;

int protect_scoreboard_count(request_rec *r, protect_scoreboard_counts *counts);

#endif

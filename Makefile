APXS ?= apxs

all:
	$(APXS) -c -I. mod_rql.c rql_scoreboard.c

install:
	$(APXS) -i -a mod_rql.la

clean:
	rm -rf .libs *.o *.lo *.la *.slo

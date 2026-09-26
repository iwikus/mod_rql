APXS ?= apxs

all:
	$(APXS) -c -I. mod_protect.c protect_scoreboard.c protect_rate.c

install:
	$(APXS) -i -a mod_protect.la

clean:
	rm -rf .libs *.o *.lo *.la *.slo

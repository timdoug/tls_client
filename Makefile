CC ?= cc
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic -O2

https_get: https_get.o tls_client.o
	$(CC) $(CFLAGS) -o $@ $^

tls_test: tls_client.c tls_client.h ct_log_table.inc
	$(CC) $(CFLAGS) -DTLS_TEST -o $@ tls_client.c

tls_client.o: tls_client.c tls_client.h ct_log_table.inc
https_get.o: https_get.c tls_client.h

getcerts:
	@set -e; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	echo "Fetching Packages.gz..."; \
	curl -fsSL https://deb.debian.org/debian/dists/stable/main/binary-all/Packages.gz \
		-o "$$tmpdir/Packages.gz"; \
	debpath=$$(gunzip -c "$$tmpdir/Packages.gz" \
		| awk '/^Package: ca-certificates$$/{found=1} found && /^Filename: /{print $$2; exit}'); \
	echo "Downloading $$debpath..."; \
	curl -fsSL "https://deb.debian.org/debian/$$debpath" -o "$$tmpdir/ca.deb"; \
	(cd "$$tmpdir" && ar x ca.deb); \
	rm -rf trust_store; \
	mkdir -p trust_store; \
	tar -xf "$$tmpdir"/data.tar.* -C trust_store \
		--strip-components=5 \
		'./usr/share/ca-certificates/mozilla/*.crt'; \
	echo "Installed $$(ls trust_store/*.crt | wc -l | tr -d ' ') certs into trust_store/"

ct_log_table.inc:
	python3 gen_ct_logs.py > $@

test: https_get tls_test
	bash test.sh -n 25

fulltest: https_get tls_test
	bash test.sh

test-local: https_get tls_test
	bash test.sh -s local

test-static:
	bash test.sh -s compile,static

test-sites-all: https_get
	bash test.sh -s pass,xfail

test-sites: https_get
	bash test.sh -s pass -n 25

test-xfail: https_get
	bash test.sh -s xfail

test-resume: https_get
	bash test.sh -s resume -n 25

clean:
	rm -f https_get tls_test *.o ct_log_table.inc
	rm -rf __pycache__

.PHONY: getcerts test fulltest test-local test-static test-sites-all test-sites test-xfail test-resume clean

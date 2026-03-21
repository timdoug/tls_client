CC ?= cc
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic -O2

# x86-64: enable AES-NI, PCLMULQDQ when available
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  CFLAGS += -maes -mpclmul -msse4.1 -mssse3
endif

https_get: https_get.o tls_client.o
	$(CC) $(CFLAGS) -o $@ $^

tls_test: tls_test.o tls_client.o
	$(CC) $(CFLAGS) -o $@ $^

tls_bench: tls_bench.o tls_client.o
	$(CC) $(CFLAGS) -o $@ $^

tls_client.o: tls_client.c tls_client.h tls_crypto.h ct_log_table.inc
https_get.o: https_get.c tls_client.h
tls_test.o: tls_test.c tls_crypto.h
tls_bench.o: tls_bench.c tls_crypto.h

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

fulltest: https_get tls_test tls_bench
	bash test.sh

test-local: https_get tls_test
	bash test.sh -s local

test-static: ct_log_table.inc
	bash test.sh -s compile,static

test-sites-all: https_get
	bash test.sh -s pass,xfail

test-sites: https_get
	bash test.sh -s pass -n 25

test-xfail: https_get
	bash test.sh -s xfail

test-resume: https_get
	bash test.sh -s resume -n 25

test-vectors: tls_test
	./tls_test

bench: tls_bench
	./tls_bench

clean:
	rm -f https_get tls_test tls_bench tls_test_x86 tls_test_portable *.o ct_log_table.inc
	rm -rf __pycache__

help:
	@echo "make test           compile, static analysis, 25 random sites + xfail + local crypto"
	@echo "make fulltest       compile, static analysis, all ~250 sites + xfail + local crypto"
	@echo "make test-vectors   RFC/NIST test vectors for all crypto primitives (32 tests)"
	@echo "make test-local     local openssl s_server cipher suite tests only"
	@echo "make test-static    compile + static analysis only"
	@echo "make test-sites     25 random site connection tests only"
	@echo "make test-sites-all all site connection tests (pass + xfail)"
	@echo "make test-xfail     expected-failure tests only"
	@echo "make test-resume    session resumption tests (local + 25 random sites)"
	@echo "make bench          crypto throughput benchmarks"
	@echo "make getcerts       download CA trust store from Debian"
	@echo "make clean          remove build artifacts"

.PHONY: help getcerts test fulltest test-local test-static test-sites-all test-sites test-xfail test-resume test-vectors bench clean

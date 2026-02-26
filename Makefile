CC ?= cc
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic -O2

tls_client: tls_client.c ct_log_table.inc
	$(CC) $(CFLAGS) -o $@ $<

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

test: tls_client
	bash test.sh -n 25

fulltest: tls_client
	bash test.sh

clean:
	rm -f tls_client ct_log_table.inc
	rm -rf __pycache__

.PHONY: getcerts test fulltest clean

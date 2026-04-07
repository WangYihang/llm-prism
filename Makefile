GOBIN ?= $(HOME)/go/bin
NIX ?= nix
# Needed on Nix < 2.24 unless enabled in nix.conf
NIX_FLAGS ?= --extra-experimental-features "nix-command flakes"

.PHONY: install install-docker

# Symlink GOBIN entries to flake-built store paths (requires Nix with flakes).
install:
	@set -e; \
	out=$$($(NIX) $(NIX_FLAGS) build .#default --no-link --print-out-paths); \
	mkdir -p "$(GOBIN)"; \
	ln -sf "$$out/bin/llm-redactor-proxy" "$(GOBIN)/llm-redactor-proxy"; \
	ln -sf "$$out/bin/llm-redactor-exec" "$(GOBIN)/llm-redactor-exec"; \
	printf 'Linked %s and %s -> %s\n' \
	  "$(GOBIN)/llm-redactor-proxy" "$(GOBIN)/llm-redactor-exec" "$$out"

install-docker:
	docker run --rm \
		-v $(CURDIR):/src \
		-v $(GOBIN):/gobin \
		-w /src golang:1.25 \
		sh -c "go build -buildvcs=false -o /gobin/llm-redactor-proxy ./cmd/llm-redactor-proxy/ && \
		       go build -buildvcs=false -o /gobin/llm-redactor-exec ./cmd/llm-redactor-exec/"

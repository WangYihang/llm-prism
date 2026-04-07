# LLM-Redactor Development Notes

## Building

### Install into `~/go/bin` (default)

Use the flake so binaries are symlinks into the Nix store (reproducible with `flake.lock`):

```bash
make install
```

This runs `nix build .#default --no-link` and links `llm-redactor-proxy` and `llm-redactor-exec` under `GOBIN` (default `~/go/bin`). Override `NIX_FLAGS` if flakes are already enabled globally.

### Docker (no Nix)

Go 1.25.4 is required. If you cannot use Nix, build via Docker:

```bash
make install-docker
```

Or manually:

```bash
docker run --rm \
  -v $(pwd):/src \
  -v $HOME/go/bin:/gobin \
  -w /src golang:1.25 \
  sh -c "go build -buildvcs=false -o /gobin/llm-redactor-proxy ./cmd/llm-redactor-proxy/ && \
         go build -buildvcs=false -o /gobin/llm-redactor-exec ./cmd/llm-redactor-exec/"
```

That copies binaries into `~/go/bin/`.

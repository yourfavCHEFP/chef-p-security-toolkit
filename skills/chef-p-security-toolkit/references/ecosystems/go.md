# Go
Manifests: `go.mod`, `go.sum`. Tests: `go test ./...`. Audit: `govulncheck ./...` (reports reachable vulns), osv-scanner.
Upgrade: `go get module@version && go mod tidy`; toolchain/stdlib issues need a newer Go version in `go.mod`/`toolchain`.

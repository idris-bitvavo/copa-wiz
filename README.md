# Copa Wiz — Copacetic scanner plugin

[Copacetic](https://github.com/project-copacetic/copacetic) can patch container images using vulnerability reports from various scanners. This repo implements a **scanner plugin** that turns **Wiz** container image scan JSON into Copacetic’s **`v1alpha1` `UpdateManifest`** format.

Scanner plugins are small CLIs named `copa-<name>` that read a report file path and print JSON on stdout. Copacetic invokes them as:

`copa-wiz /path/to/wiz-report.json`

Learn more: [Copacetic scanner plugins](https://project-copacetic.github.io/copacetic/website/scanner-plugins).

## What it does

- Reads Wiz CI/CD / CLI JSON where **`result.osPackages`** lists distro packages and each entry has **`vulnerabilities[]`** with **`name`** (e.g. CVE) and **`fixedVersion`**.
- Emits one **`updates[]`** row per **fixable** vulnerability (non-empty `fixedVersion`), matching how the built-in **Trivy** parser works. Copacetic then **deduplicates by package** and keeps the **latest** valid fixed version.
- Sets **`metadata.os.type`** to **`debian`** and **`metadata.os.version`** from dpkg version strings (e.g. `deb12u1` → **`12`**) so Copacetic can select the right tooling image (`debian:12-slim`).
- Sets **`metadata.config.arch`** to **`amd64`** by default (Wiz reports often omit image architecture).

### Out of scope (for now)

- **Language / app packages** (e.g. `result.cpes`, `result.libraries`, Python `pip` fixes) — Copacetic’s Debian/Ubuntu path targets **dpkg** OS packages; those findings are ignored.
- **RPM/Alpine** images — this plugin expects **Debian-style** `debNNu` version suffixes to infer the OS release. Extend [`internal/wiz/wiz.go`](internal/wiz/wiz.go) if you need other distros.

## Input format

Compatible with Wiz exports where:

- Top level includes **`result`**.
- **`result.osPackages`** is a non-empty array of objects with **`name`**, **`version`**, and **`vulnerabilities`**.

A **minimal** example is in [`testdata/wiz_minimal.json`](testdata/wiz_minimal.json): two **`osPackages`** rows taken from the real scan (`openssl` and `libssl3`), same versions as [`testdata/wiz_full_sample.json`](testdata/wiz_full_sample.json). The first has a **fixable** CVE; the second keeps the same CVE but an **empty `fixedVersion`** to show that entries without a fix are skipped. A **full** export is in [`testdata/wiz_full_sample.json`](testdata/wiz_full_sample.json).

## Build

Requires **Go** (see `go.mod`) and **make**.

```shell
make
# binary: dist/$(go env GOOS)_$(go env GOARCH)/release/copa-wiz
```

The executable lives under **`cmd/copa-wiz`** so `go install` produces a binary named **`copa-wiz`** (not the repository folder name).

## Install on PATH (required for `copa patch`)

Copacetic runs **`copa-wiz`** with **`exec.LookPath`**: the binary must exist in **`$PATH`** in the **same environment** where you run **`copa`** (your laptop, CI job, or container). If you see `executable file not found in $PATH`, the plugin is not installed or your PATH does not include its directory.

### Option A — `go install` (recommended)

From a clone of this repository:

```shell
go install ./cmd/copa-wiz
```

This installs to **`$(go env GOBIN)`** if set, otherwise **`$(go env GOPATH)/bin`**. Ensure that directory is on PATH, for example:

```shell
export PATH="$(go env GOPATH)/bin:$PATH"
# or, if you use GOBIN:
export PATH="$(go env GOBIN):$PATH"
```

Or use **`make install`**, which runs the same `go install`.

Verify:

```shell
which copa-wiz
copa-wiz testdata/wiz_minimal.json | head -c 200
```

### Option B — `make build` and extend PATH

```shell
make
export PATH="$PATH:$(pwd)/dist/$(go env GOOS)_$(go env GOARCH)/release"
```

### CI / Docker

If **`copa`** runs inside a container or remote runner, install **`copa-wiz`** into that same image or job (copy the binary or run `go install` there). Mounting only the report file is not enough; the **`copa-wiz`** executable must be present where **`copa`** executes.

## Usage

```shell
# After copa-wiz is on PATH (see above)
copa-wiz testdata/wiz_minimal.json | jq .

copa patch -i "$IMAGE" -r /path/to/wiz-report.json --scanner wiz
```

## Development

```shell
go test ./...
```

## Origins

This project was derived from the official [scanner-plugin-template](https://github.com/project-copacetic/scanner-plugin-template) and adapted for **Wiz** container scan JSON.

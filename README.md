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
- **RPM/Alpine** images — this plugin expects **Debian-style** `debNNu` version suffixes to infer the OS release. Extend `wiz.go` if you need other distros.

## Input format

Compatible with Wiz exports where:

- Top level includes **`result`**.
- **`result.osPackages`** is a non-empty array of objects with **`name`**, **`version`**, and **`vulnerabilities`**.

A **minimal** example is in [`testdata/wiz_minimal.json`](testdata/wiz_minimal.json). A **real** container scan sample is in [`testdata/wiz_full_sample.json`](testdata/wiz_full_sample.json).

## Build

Requires **Go** (see `go.mod`) and **make**.

```shell
make
# binary: dist/$(go env GOOS)_$(go env GOARCH)/release/copa-wiz
```

## Usage

```shell
# Build and put copa-wiz on PATH
export PATH="$PATH:$(pwd)/dist/$(go env GOOS)_$(go env GOARCH)/release"

# Inspect normalized manifest
copa-wiz testdata/wiz_minimal.json | jq .

# Patch an image with Copacetic (report from Wiz)
copa patch -i "$IMAGE" -r /path/to/wiz-report.json --scanner wiz
```

## Development

```shell
go test ./...
```

## Origins

This project was derived from the official [scanner-plugin-template](https://github.com/project-copacetic/scanner-plugin-template) and adapted for **Wiz** container scan JSON.

# Copa Wiz — Copacetic scanner plugin

[Copacetic](https://github.com/project-copacetic/copacetic) can patch container images using vulnerability reports from various scanners. This repo implements a **scanner plugin** that turns **Wiz** container image scan JSON into Copacetic’s **`v1alpha1` `UpdateManifest`** format.

Scanner plugins are small CLIs named `copa-<name>` that read a report file path and print JSON on stdout. Copacetic invokes them as:

`copa-wiz /path/to/wiz-report.json`

Learn more: [Copacetic scanner plugins](https://project-copacetic.github.io/copacetic/website/scanner-plugins).

## What it does

- Reads Wiz CI/CD / CLI JSON where **`result.osPackages`** lists distro packages and each entry has **`vulnerabilities[]`** with **`name`** (e.g. CVE) and **`fixedVersion`**.
- Emits one **`updates[]`** row per **fixable** vulnerability (non-empty `fixedVersion`), matching how the built-in **Trivy** parser works. Copacetic then **deduplicates by package** and keeps the **latest** valid fixed version.
- Infers **`metadata.os`** for:
  - **Debian** — `type=debian`, version from `debNNu` / `+debNN` (e.g. **`12`**).
  - **Ubuntu** — `type=ubuntu` from `ubuntu` version tokens, `ubuntu.com` sources, `ubuntu:` image refs, or codenames (`jammy` → **`22.04`**); version from `YY.04` in package strings or image tags (`ubuntu:22.04`).
  - **Alpine** — `type=alpine` from APK / `-rN` / `alpinelinux.org` / `alpine:` image tags; version from the image tag (`alpine:3.22.4` → **`3.22.4`**). A version is **required when updates exist** (Copacetic rejects empty `metadata.os.version`).
  - **Amazon Linux** — `type=amazon` from `.amznYYYY`, ALAS sources, or `amazonlinux` / `amazoncorretto` images.
  - **Red Hat** — `type=redhat` only with RHEL-specific evidence (`access.redhat.com` sources and/or `rhel` / `redhat` / `ubi` image names); release from `.elN`. Plain `.elN` alone is **not** enough (shared with CentOS/Alma/Rocky).
  - **CBL-Mariner** — `type=cbl-mariner` from `.cmN` / Mariner vuln sources / `mariner` image names (e.g. **`2.0`**).
  - **Azure Linux** — `type=azurelinux` from `.azlN`, `azurelinux` image names, or Azure Linux sources (e.g. **`3.0`**); not classified as CBL-Mariner.
- Reports with **no `result.osPackages`**, or a **supported OS with no fixable `fixedVersion`s**, succeed with an **empty `updates` list**.
- Reports that **have `osPackages` but do not match a supported distro** return an **error** (with package-manager hints when present) so new OS families stay visible.
- Sets **`metadata.config.arch`** to **`amd64`** by default (Wiz reports often omit image architecture).

### Out of scope (for now)

- **Language / app packages** (e.g. `result.cpes`, `result.libraries`) — ignored; empty OS package lists do not fail the plugin.
- **Other RPM rebuilds** (CentOS, Rocky, Alma, SUSE, …) — still error until added with distro-specific detectors in `wiz.go`.

## Input format

Compatible with Wiz exports where:

- Top level includes **`result`**.
- **`result.osPackages`** lists objects with **`name`**, **`version`**, and **`vulnerabilities`** (may be null/empty for library-only scans).

Minimal fixtures: Debian / Alpine / Amazon / Ubuntu / Red Hat / Mariner under `testdata/wiz_*_minimal.json`. CI patch job uses [`testdata/debian12-wiz-report.json`](testdata/debian12-wiz-report.json) with `debian:12-slim` (Debian 11 / `nginx:1.21.6` is EOL). Library-only empty-OS fixture: [`testdata/astral.json`](testdata/astral.json).

## Build

Requires **Go** (see `go.mod`) and **make**.

```shell
make
# binary: dist/$(go env GOOS)_$(go env GOARCH)/release/copa-wiz
```

## Usage

```shell
make

# Prefer installing over a system copy so an older /usr/local/bin/copa-wiz
# does not shadow the build (check with: which -a copa-wiz).
sudo install -m 0755 \
  "$(pwd)/dist/$(go env GOOS)_$(go env GOARCH)/release/copa-wiz" \
  /usr/local/bin/copa-wiz

# Or put the build directory first on PATH for this shell only:
# export PATH="$(pwd)/dist/$(go env GOOS)_$(go env GOARCH)/release:$PATH"

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
 
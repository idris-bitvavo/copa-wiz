package wiz

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

// testdata paths: tests run with cwd = package dir (internal/wiz).
func testPath(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func Test_parseReport(t *testing.T) {
	t.Parallel()
	got, err := parseReport(testPath("wiz_minimal.json"))
	if err != nil {
		t.Fatalf("parseReport: %v", err)
	}
	if got.Result == nil || got.Result.Typename != "CICDDiskScanResult" {
		t.Fatalf("unexpected result: %+v", got.Result)
	}
	if len(got.Result.OSPackages) != 2 {
		t.Fatalf("expected 2 os packages, got %d", len(got.Result.OSPackages))
	}
}

func Test_parseReport_allowsEmptyOSPackages(t *testing.T) {
	t.Parallel()
	got, err := parseReport(testPath("astral.json"))
	if err != nil {
		t.Fatalf("parseReport astral: %v", err)
	}
	if got.Result == nil {
		t.Fatal("expected result")
	}
	if len(got.Result.OSPackages) != 0 {
		t.Fatalf("expected 0 osPackages, got %d", len(got.Result.OSPackages))
	}
}

func Test_parseReport_errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		file    string
		wantErr bool
	}{
		{"missing file", testPath("nonexistent_file.json"), true},
		{"invalid json", testPath("invalid_report.json"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseReport(tt.file)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_parseReport_rejectsLargeFile(t *testing.T) {
	t.Parallel()
	f, err := os.CreateTemp(t.TempDir(), "wiz-too-large-*.json")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Errorf("close temp file: %v", cerr)
		}
	}()

	_, err = f.WriteString(strings.Repeat("a", int(maxReportSizeBytes)+1))
	if err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	if _, err := parseReport(f.Name()); err == nil {
		t.Fatal("expected parseReport to reject oversized file")
	}
}

func TestParser_Parse(t *testing.T) {
	t.Parallel()
	p := NewParser()
	want := &v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
		Metadata: v1alpha1.Metadata{
			OS: v1alpha1.OS{
				Type:    "debian",
				Version: "12",
			},
			Config: v1alpha1.Config{Arch: "amd64"},
		},
		Updates: []v1alpha1.UpdatePackage{
			{
				Name:             "openssl",
				InstalledVersion: "3.0.16-1~deb12u1",
				FixedVersion:     "3.0.18-1~deb12u2",
				VulnerabilityID:  "CVE-2025-15467",
			},
		},
	}
	got, err := p.Parse(testPath("wiz_minimal.json"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parse() = %#v\nwant %#v", got, want)
	}
}

func TestParser_Parse_nginxReport(t *testing.T) {
	t.Parallel()
	p := NewParser()
	manifest, err := p.Parse(testPath("nginx-wiz-report.json"))
	if err != nil {
		t.Fatalf("Parse nginx Wiz report: %v", err)
	}
	if manifest.Metadata.OS.Type != "debian" || manifest.Metadata.OS.Version != "11" {
		t.Fatalf("OS metadata: got %+v", manifest.Metadata.OS)
	}
	if len(manifest.Updates) < 3 {
		t.Fatalf("expected at least 3 OS-package updates from nginx report, got %d", len(manifest.Updates))
	}
}

func TestParser_Parse_alpineMinimal(t *testing.T) {
	t.Parallel()
	p := NewParser()
	want := &v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
		Metadata: v1alpha1.Metadata{
			OS: v1alpha1.OS{
				Type:    "alpine",
				Version: "3.22.4",
			},
			Config: v1alpha1.Config{Arch: "amd64"},
		},
		Updates: []v1alpha1.UpdatePackage{
			{
				Name:             "libcrypto3",
				InstalledVersion: "3.5.6-r0",
				FixedVersion:     "3.5.8-r0",
				VulnerabilityID:  "CVE-2026-63073",
			},
			{
				Name:             "libcrypto3",
				InstalledVersion: "3.5.6-r0",
				FixedVersion:     "3.5.8-r0",
				VulnerabilityID:  "CVE-2026-75803",
			},
		},
	}
	got, err := p.Parse(testPath("wiz_alpine_minimal.json"))
	if err != nil {
		t.Fatalf("Parse alpine minimal: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parse() = %#v\nwant %#v", got, want)
	}
}

func TestParser_Parse_alpineMissingVersionWithUpdatesErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "alpine-no-tag.json")
	content := `{
  "result": {
    "__typename": "CICDDiskScanResult",
    "osPackages": [
      {
        "name": "libcrypto3",
        "version": "3.5.6-r0",
        "vulnerabilities": [
          {"name": "CVE-1", "fixedVersion": "3.5.8-r0", "source": "https://security.alpinelinux.org/vuln/CVE-1"}
        ]
      }
    ],
    "vulnerableSBOMArtifactsByNameVersion": [
      {"type": {"osPackageManager": "APK"}}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := NewParser().Parse(path)
	if err == nil {
		t.Fatal("expected Alpine release inference error when updates exist without image tag")
	}
	if !strings.Contains(err.Error(), "Alpine release") {
		t.Fatalf("error = %v, want Alpine release", err)
	}
}

func TestParser_Parse_alpineMissingVersionWithoutUpdatesOK(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "alpine-unfixed.json")
	content := `{
  "result": {
    "__typename": "CICDDiskScanResult",
    "osPackages": [
      {
        "name": "busybox",
        "version": "1.37.0-r20",
        "vulnerabilities": [
          {"name": "CVE-1", "fixedVersion": null, "source": "https://security.alpinelinux.org/vuln/CVE-1"}
        ]
      }
    ],
    "vulnerableSBOMArtifactsByNameVersion": [
      {"type": {"osPackageManager": "APK"}}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := NewParser().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Metadata.OS.Type != "alpine" || got.Metadata.OS.Version != "" {
		t.Fatalf("OS metadata: got %+v", got.Metadata.OS)
	}
	if len(got.Updates) != 0 {
		t.Fatalf("updates: got %d, want 0", len(got.Updates))
	}
}

func TestParser_Parse_amazonMinimal(t *testing.T) {
	t.Parallel()
	p := NewParser()
	want := &v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
		Metadata: v1alpha1.Metadata{
			OS: v1alpha1.OS{
				Type:    "amazon",
				Version: "2023",
			},
			Config: v1alpha1.Config{Arch: "amd64"},
		},
		Updates: []v1alpha1.UpdatePackage{
			{
				Name:             "openssl-libs",
				InstalledVersion: "3.5.7-2.amzn2023.0.1",
				FixedVersion:     "1:3.5.7-2.amzn2023.0.2",
				VulnerabilityID:  "CVE-2026-14456",
			},
			{
				Name:             "python3-pip-wheel",
				InstalledVersion: "21.3.1-2.amzn2023.0.20",
				FixedVersion:     "21.3.1-2.amzn2023.0.21",
				VulnerabilityID:  "CVE-2026-45409",
			},
		},
	}
	got, err := p.Parse(testPath("wiz_amazon_minimal.json"))
	if err != nil {
		t.Fatalf("Parse amazon minimal: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parse() = %#v\nwant %#v", got, want)
	}
}

func TestParser_Parse_ubuntuMinimal(t *testing.T) {
	t.Parallel()
	got, err := NewParser().Parse(testPath("wiz_ubuntu_minimal.json"))
	if err != nil {
		t.Fatalf("Parse ubuntu minimal: %v", err)
	}
	if got.Metadata.OS.Type != "ubuntu" || got.Metadata.OS.Version != "22.04" {
		t.Fatalf("OS metadata: got %+v", got.Metadata.OS)
	}
	if len(got.Updates) != 1 || got.Updates[0].Name != "libc6" {
		t.Fatalf("updates: %#v", got.Updates)
	}
}

func TestParser_Parse_redhatMinimal(t *testing.T) {
	t.Parallel()
	got, err := NewParser().Parse(testPath("wiz_redhat_minimal.json"))
	if err != nil {
		t.Fatalf("Parse redhat minimal: %v", err)
	}
	if got.Metadata.OS.Type != "redhat" || got.Metadata.OS.Version != "8" {
		t.Fatalf("OS metadata: got %+v", got.Metadata.OS)
	}
	if len(got.Updates) != 1 {
		t.Fatalf("updates: got %d", len(got.Updates))
	}
}

func TestParser_Parse_marinerMinimal(t *testing.T) {
	t.Parallel()
	got, err := NewParser().Parse(testPath("wiz_mariner_minimal.json"))
	if err != nil {
		t.Fatalf("Parse mariner minimal: %v", err)
	}
	if got.Metadata.OS.Type != "cbl-mariner" || got.Metadata.OS.Version != "2.0" {
		t.Fatalf("OS metadata: got %+v", got.Metadata.OS)
	}
	if len(got.Updates) != 1 {
		t.Fatalf("updates: got %d", len(got.Updates))
	}
}

func TestParser_Parse_noOSPackages(t *testing.T) {
	t.Parallel()
	got, err := NewParser().Parse(testPath("astral.json"))
	if err != nil {
		t.Fatalf("Parse astral.json: %v", err)
	}
	if got.Updates == nil || len(got.Updates) != 0 {
		t.Fatalf("expected empty updates, got %#v", got.Updates)
	}
}

func TestParser_Parse_unsupportedOSErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "unsupported.json")
	// Unknown package manager / version scheme — must remain an error.
	content := `{
  "result": {
    "__typename": "CICDDiskScanResult",
    "osPackages": [
      {
        "name": "bash",
        "version": "5.1.8-2.unknown1",
        "vulnerabilities": [
          {"name": "CVE-1", "fixedVersion": "5.1.8-3.unknown1", "source": "https://example.com/vuln"}
        ]
      }
    ],
    "vulnerableSBOMArtifactsByNameVersion": [
      {"type": {"osPackageManager": "UNKNOWN_PM"}}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := NewParser().Parse(path)
	if err == nil {
		t.Fatal("expected unsupported OS error")
	}
	if !strings.Contains(err.Error(), "unsupported OS") {
		t.Fatalf("error = %v, want unsupported OS", err)
	}
	if !strings.Contains(err.Error(), "UNKNOWN_PM") {
		t.Fatalf("error = %v, want package manager hint", err)
	}
}

func Test_inferDebianRelease(t *testing.T) {
	t.Parallel()
	pkgs := []osPackage{
		{Name: "openssl", Version: "3.0.16-1~deb12u1"},
	}
	if v := inferDebianRelease(pkgs); v != "12" {
		t.Fatalf("inferDebianRelease = %q, want 12", v)
	}
}

func Test_inferOSAndArch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		report      *report
		wantType    string
		wantVersion string
	}{
		{
			name: "debian from debNu",
			report: &report{Result: &diskScanResult{OSPackages: []osPackage{
				{Name: "openssl", Version: "3.0.16-1~deb12u1"},
			}}},
			wantType: "debian", wantVersion: "12",
		},
		{
			name: "ubuntu from ubuntu token and jammy tag",
			report: &report{
				ScanOriginResource: &scanOriginResource{Name: "eclipse-temurin:17-jre-jammy"},
				Result: &diskScanResult{OSPackages: []osPackage{
					{Name: "libc6", Version: "2.35-0ubuntu3.14", Vulnerabilities: []vulnerability{
						{FixedVersion: "2.35-0ubuntu3.15", Source: "https://ubuntu.com/security/CVE-1"},
					}},
				}},
			},
			wantType: "ubuntu", wantVersion: "22.04",
		},
		{
			name: "ubuntu from numeric image tag when packages lack YY.04",
			report: &report{
				ScanOriginResource: &scanOriginResource{Name: "docker.io/library/ubuntu:22.04"},
				Result: &diskScanResult{OSPackages: []osPackage{
					{Name: "libc6", Version: "2.35-0ubuntu3.14", Vulnerabilities: []vulnerability{
						{Name: "CVE-1", FixedVersion: "2.35-0ubuntu3.15", Source: "https://ubuntu.com/security/CVE-1"},
					}},
				}},
			},
			wantType: "ubuntu", wantVersion: "22.04",
		},
		{
			name: "ubuntu from YY.04 in package version",
			report: &report{Result: &diskScanResult{OSPackages: []osPackage{
				{Name: "curl", Version: "4.9-2ubuntu0.24.04.1"},
			}}},
			wantType: "ubuntu", wantVersion: "24.04",
		},
		{
			name: "alpine from apk versions and image tag",
			report: &report{
				ScanOriginResource: &scanOriginResource{Name: "ghcr.io/bitvavo/alpine:3.22.4"},
				Result: &diskScanResult{OSPackages: []osPackage{
					{Name: "libcrypto3", Version: "3.5.6-r0"},
				}},
			},
			wantType: "alpine", wantVersion: "3.22.4",
		},
		{
			name: "alpine without image tag has empty version",
			report: &report{Result: &diskScanResult{
				OSPackages: []osPackage{
					{Name: "libssl3", Version: "3.5.6-r0", Vulnerabilities: []vulnerability{
						{Name: "CVE-1", FixedVersion: "3.5.8-r0"},
					}},
				},
				VulnerableSBOMArtifactsByNameVersion: []sbomArtifact{
					{Type: &sbomType{OSPackageManager: "APK"}},
				},
			}},
			wantType: "alpine", wantVersion: "",
		},
		{
			name: "amazon from amzn version",
			report: &report{Result: &diskScanResult{OSPackages: []osPackage{
				{Name: "openssl-libs", Version: "3.5.7-2.amzn2023.0.1"},
			}}},
			wantType: "amazon", wantVersion: "2023",
		},
		{
			name: "redhat from access.redhat.com and el8",
			report: &report{Result: &diskScanResult{OSPackages: []osPackage{
				{Name: "bash", Version: "4.4.20-5.el8", Vulnerabilities: []vulnerability{
					{FixedVersion: "4.4.20-6.el8", Source: "https://access.redhat.com/errata/RHSA-1"},
				}},
			}}},
			wantType: "redhat", wantVersion: "8",
		},
		{
			name: "redhat from ubi image marker and el9",
			report: &report{
				ScanOriginResource: &scanOriginResource{Name: "registry.access.redhat.com/ubi9/ubi:latest"},
				Result: &diskScanResult{OSPackages: []osPackage{
					{Name: "bash", Version: "5.1.8-2.el9"},
				}},
			},
			wantType: "redhat", wantVersion: "9",
		},
		{
			name: "el8 alone is not redhat (shared by centos/alma/rocky)",
			report: &report{Result: &diskScanResult{OSPackages: []osPackage{
				{Name: "bash", Version: "4.4.20-5.el8", Vulnerabilities: []vulnerability{
					{FixedVersion: "4.4.20-6.el8", Source: "https://errata.rockylinux.org/"},
				}},
			}}},
			wantType: "", wantVersion: "",
		},
		{
			name: "centos image with el8 is still unsupported without rhel markers",
			report: &report{
				ScanOriginResource: &scanOriginResource{Name: "quay.io/centos/centos:stream8"},
				Result: &diskScanResult{OSPackages: []osPackage{
					{Name: "bash", Version: "4.4.20-5.el8"},
				}},
			},
			wantType: "", wantVersion: "",
		},
		{
			name: "cbl-mariner from cm2",
			report: &report{Result: &diskScanResult{OSPackages: []osPackage{
				{Name: "openssl", Version: "1.1.1k-35.cm2"},
			}}},
			wantType: "cbl-mariner", wantVersion: "2.0",
		},
		{
			name: "azurelinux from azl3 is not cbl-mariner",
			report: &report{
				ScanOriginResource: &scanOriginResource{Name: "mcr.microsoft.com/azurelinux/base/core:3.0"},
				Result: &diskScanResult{OSPackages: []osPackage{
					{Name: "openssl", Version: "3.1.4-1.azl3", Vulnerabilities: []vulnerability{
						{FixedVersion: "3.1.4-2.azl3", Source: "https://github.com/microsoft/azurelinux"},
					}},
				}},
			},
			wantType: "azurelinux", wantVersion: "3.0",
		},
		{
			name: "azurelinux image without azl version still typed azurelinux",
			report: &report{
				ScanOriginResource: &scanOriginResource{Name: "mcr.microsoft.com/azurelinux/base/core:3.0"},
				Result: &diskScanResult{OSPackages: []osPackage{
					{Name: "filesystem", Version: "1.1-19"},
				}},
			},
			wantType: "azurelinux", wantVersion: "3.0",
		},
		{
			name: "mariner image stays cbl-mariner",
			report: &report{
				ScanOriginResource: &scanOriginResource{Name: "ghcr.io/bitvavo/azure-watson/agent/agent_mariner:1.21.13.0"},
				Result: &diskScanResult{OSPackages: []osPackage{
					{Name: "openssl", Version: "1.1.1k-35.cm2"},
				}},
			},
			wantType: "cbl-mariner", wantVersion: "2.0",
		},
		{
			name: "debian wins over ubuntu-looking image when deb marker present",
			report: &report{
				ScanOriginResource: &scanOriginResource{Name: "app:jammy"},
				Result: &diskScanResult{OSPackages: []osPackage{
					{Name: "openssl", Version: "3.0.16-1~deb12u1"},
				}},
			},
			wantType: "debian", wantVersion: "12",
		},
		{
			name: "unknown",
			report: &report{Result: &diskScanResult{OSPackages: []osPackage{
				{Name: "foo", Version: "1.2.3"},
			}}},
			wantType: "", wantVersion: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotType, gotVersion, gotArch := inferOSAndArch(tt.report)
			if gotType != tt.wantType || gotVersion != tt.wantVersion {
				t.Fatalf("inferOSAndArch() = (%q, %q), want (%q, %q)", gotType, gotVersion, tt.wantType, tt.wantVersion)
			}
			if gotArch != "amd64" {
				t.Fatalf("arch = %q, want amd64", gotArch)
			}
		})
	}
}

func TestParser_Parse_ubuntuNumericImageTag(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ubuntu-numeric.json")
	content := `{
  "result": {
    "__typename": "CICDDiskScanResult",
    "osPackages": [
      {
        "name": "libc6",
        "version": "2.35-0ubuntu3.14",
        "vulnerabilities": [
          {"name": "CVE-1", "fixedVersion": "2.35-0ubuntu3.15", "source": "https://ubuntu.com/security/CVE-1"}
        ]
      }
    ]
  },
  "scanOriginResource": {"name": "docker.io/library/ubuntu:22.04"}
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := NewParser().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Metadata.OS.Type != "ubuntu" || got.Metadata.OS.Version != "22.04" {
		t.Fatalf("OS metadata: got %+v", got.Metadata.OS)
	}
	if len(got.Updates) != 1 {
		t.Fatalf("updates: got %d", len(got.Updates))
	}
}

func TestParser_Parse_elOnlyIsUnsupported(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "rocky-el.json")
	content := `{
  "result": {
    "__typename": "CICDDiskScanResult",
    "osPackages": [
      {
        "name": "bash",
        "version": "5.1.8-2.el9",
        "vulnerabilities": [
          {"name": "CVE-1", "fixedVersion": "5.1.8-3.el9", "source": "https://errata.rockylinux.org/"}
        ]
      }
    ],
    "vulnerableSBOMArtifactsByNameVersion": [
      {"type": {"osPackageManager": "RPM"}}
    ]
  },
  "scanOriginResource": {"name": "rockylinux:9"}
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := NewParser().Parse(path)
	if err == nil {
		t.Fatal("expected unsupported OS error for rocky/.elN without RHEL markers")
	}
	if !strings.Contains(err.Error(), "unsupported OS") {
		t.Fatalf("error = %v, want unsupported OS", err)
	}
}

func TestParser_Parse_azurelinux(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "azurelinux.json")
	content := `{
  "result": {
    "__typename": "CICDDiskScanResult",
    "osPackages": [
      {
        "name": "openssl",
        "version": "3.1.4-1.azl3",
        "vulnerabilities": [
          {"name": "CVE-1", "fixedVersion": "3.1.4-2.azl3", "source": "https://github.com/microsoft/azurelinux"}
        ]
      }
    ],
    "vulnerableSBOMArtifactsByNameVersion": [
      {"type": {"osPackageManager": "RPM"}}
    ]
  },
  "scanOriginResource": {"name": "mcr.microsoft.com/azurelinux/base/core:3.0"}
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := NewParser().Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Metadata.OS.Type != "azurelinux" || got.Metadata.OS.Version != "3.0" {
		t.Fatalf("OS metadata: got %+v", got.Metadata.OS)
	}
	if len(got.Updates) != 1 {
		t.Fatalf("updates: got %d", len(got.Updates))
	}
}

func TestParser_Parse_azurelinuxImageWithoutReleaseErrorsWhenFixable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "azurelinux-norelease.json")
	// Image name contains azurelinux but no :N tag and packages lack .azlN.
	content := `{
  "result": {
    "__typename": "CICDDiskScanResult",
    "osPackages": [
      {
        "name": "openssl",
        "version": "3.1.4-1",
        "vulnerabilities": [
          {"name": "CVE-1", "fixedVersion": "3.1.4-2", "source": "https://example.com"}
        ]
      }
    ]
  },
  "scanOriginResource": {"name": "example.com/azurelinux/custom"}
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := NewParser().Parse(path)
	if err == nil {
		t.Fatal("expected release inference error")
	}
	if !strings.Contains(err.Error(), "Azure Linux release") {
		t.Fatalf("error = %v, want Azure Linux release", err)
	}
}

package main

import (
	"path/filepath"
	"reflect"
	"testing"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

func Test_parseWizReport(t *testing.T) {
	t.Parallel()
	got, err := parseWizReport("testdata/wiz_minimal.json")
	if err != nil {
		t.Fatalf("parseWizReport: %v", err)
	}
	if got.Result == nil || got.Result.Typename != "CICDDiskScanResult" {
		t.Fatalf("unexpected result: %+v", got.Result)
	}
	if len(got.Result.OSPackages) != 2 {
		t.Fatalf("expected 2 os packages, got %d", len(got.Result.OSPackages))
	}
}

func Test_parseWizReport_errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		file    string
		wantErr bool
	}{
		{"missing file", "testdata/nonexistent_file.json", true},
		{"invalid json", "testdata/invalid_report.json", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseWizReport(tt.file)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWizParser_parse(t *testing.T) {
	t.Parallel()
	p := newWizParser()
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
	got, err := p.parse("testdata/wiz_minimal.json")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parse() = %#v\nwant %#v", got, want)
	}
}

func TestWizParser_parse_fullSample(t *testing.T) {
	t.Parallel()
	p := newWizParser()
	manifest, err := p.parse(filepath.Join("testdata", "wiz_full_sample.json"))
	if err != nil {
		t.Fatalf("parse full Wiz sample: %v", err)
	}
	if manifest.Metadata.OS.Type != "debian" || manifest.Metadata.OS.Version != "12" {
		t.Fatalf("OS metadata: got %+v", manifest.Metadata.OS)
	}
	// Full sample includes 3 OS packages with fixable critical vulns in osPackages
	// (additional findings may appear under cpes/libraries, which we skip for dpkg).
	if len(manifest.Updates) < 3 {
		t.Fatalf("expected at least 3 OS-package updates from full sample, got %d", len(manifest.Updates))
	}
}

func Test_inferDebianRelease(t *testing.T) {
	t.Parallel()
	pkgs := []wizOSPackage{
		{Name: "openssl", Version: "3.0.16-1~deb12u1"},
	}
	if v := inferDebianRelease(pkgs); v != "12" {
		t.Fatalf("inferDebianRelease = %q, want 12", v)
	}
}

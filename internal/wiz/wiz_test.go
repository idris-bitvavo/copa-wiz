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

	// Write one byte above the configured limit.
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

func TestParser_Parse_fullSample(t *testing.T) {
	t.Parallel()
	p := NewParser()
	manifest, err := p.Parse(testPath("wiz_full_sample.json"))
	if err != nil {
		t.Fatalf("Parse full Wiz sample: %v", err)
	}
	if manifest.Metadata.OS.Type != "debian" || manifest.Metadata.OS.Version != "12" {
		t.Fatalf("OS metadata: got %+v", manifest.Metadata.OS)
	}
	if len(manifest.Updates) < 3 {
		t.Fatalf("expected at least 3 OS-package updates from full sample, got %d", len(manifest.Updates))
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

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

// JSON shapes for Wiz CLI / CI/CD container image scan export (subset).

type wizReport struct {
	Result *wizDiskScanResult `json:"result"`
}

type wizDiskScanResult struct {
	Typename   string         `json:"__typename"`
	OSPackages []wizOSPackage `json:"osPackages"`
}

type wizOSPackage struct {
	Name            string             `json:"name"`
	Version         string             `json:"version"`
	Vulnerabilities []wizVulnerability `json:"vulnerabilities"`
}

type wizVulnerability struct {
	Name         string `json:"name"`
	FixedVersion string `json:"fixedVersion"`
}

var debReleaseRe = regexp.MustCompile(`deb(\d+)u`)

func parseWizReport(path string) (*wizReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r wizReport
	if err = json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("wiz report JSON: %w", err)
	}
	if r.Result == nil {
		return nil, fmt.Errorf("wiz report: missing top-level \"result\"")
	}
	if len(r.Result.OSPackages) == 0 {
		return nil, fmt.Errorf("wiz report: no result.osPackages (need OS package scan results)")
	}
	return &r, nil
}

// inferOSAndArch sets Copacetic metadata from Wiz output. Wiz does not always
// include explicit distro/arch. Debian release is inferred from dpkg version
// suffixes like deb12u1 (Debian 12 / bookworm). Ubuntu is not inferred here
// (Wiz versions are ambiguous); use a Debian-based report or extend this logic.
func inferOSAndArch(pkgs []wizOSPackage) (osType, osVersion, arch string) {
	arch = "amd64" // Wiz JSON often omits image arch; override via workflow if needed.

	debVer := inferDebianRelease(pkgs)
	if debVer != "" {
		return "debian", debVer, arch
	}
	return "debian", "", arch
}

func inferDebianRelease(pkgs []wizOSPackage) string {
	for _, p := range pkgs {
		for _, s := range []string{p.Version} {
			if m := debReleaseRe.FindStringSubmatch(s); len(m) == 2 {
				return m[1]
			}
		}
		for _, v := range p.Vulnerabilities {
			if m := debReleaseRe.FindStringSubmatch(v.FixedVersion); len(m) == 2 {
				return m[1]
			}
		}
	}
	// e.g. 1.2.3+deb12u1
	alt := regexp.MustCompile(`\+deb(\d+)`)
	for _, p := range pkgs {
		if m := alt.FindStringSubmatch(p.Version); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

type WizParser struct{}

func newWizParser() *WizParser {
	return &WizParser{}
}

func (w *WizParser) parse(file string) (*v1alpha1.UpdateManifest, error) {
	report, err := parseWizReport(file)
	if err != nil {
		return nil, err
	}

	osType, osVersion, arch := inferOSAndArch(report.Result.OSPackages)
	if osVersion == "" {
		return nil, fmt.Errorf("could not infer Debian release from package versions (expected patterns like deb12u1 in versions)")
	}

	updates := v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
		Metadata: v1alpha1.Metadata{
			OS: v1alpha1.OS{
				Type:    osType,
				Version: osVersion,
			},
			Config: v1alpha1.Config{
				Arch: arch,
			},
		},
	}

	// Same pattern as upstream Trivy parser: one row per fixable vuln; Copacetic
	// merges by package and picks the latest fixed version.
	for i := range report.Result.OSPackages {
		pkg := &report.Result.OSPackages[i]
		for j := range pkg.Vulnerabilities {
			v := &pkg.Vulnerabilities[j]
			if v.FixedVersion == "" {
				continue
			}
			vulnID := strings.TrimSpace(v.Name)
			if vulnID == "" {
				vulnID = "UNKNOWN"
			}
			updates.Updates = append(updates.Updates, v1alpha1.UpdatePackage{
				Name:             pkg.Name,
				InstalledVersion: pkg.Version,
				FixedVersion:     v.FixedVersion,
				VulnerabilityID:  vulnID,
			})
		}
	}

	if len(updates.Updates) == 0 {
		return nil, fmt.Errorf("wiz report: no vulnerabilities with non-empty fixedVersion under result.osPackages")
	}

	return &updates, nil
}

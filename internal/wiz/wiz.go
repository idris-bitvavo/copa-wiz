package wiz

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

type report struct {
	Result *diskScanResult `json:"result"`
}

type diskScanResult struct {
	Typename   string       `json:"__typename"`
	OSPackages []osPackage  `json:"osPackages"`
}

type osPackage struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type vulnerability struct {
	Name         string `json:"name"`
	FixedVersion string `json:"fixedVersion"`
}

var debReleaseRe = regexp.MustCompile(`deb(\d+)u`)

func parseReport(path string) (*report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r report
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

func inferOSAndArch(pkgs []osPackage) (osType, osVersion, arch string) {
	arch = "amd64"

	debVer := inferDebianRelease(pkgs)
	if debVer != "" {
		return "debian", debVer, arch
	}
	return "debian", "", arch
}

func inferDebianRelease(pkgs []osPackage) string {
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
	alt := regexp.MustCompile(`\+deb(\d+)`)
	for _, p := range pkgs {
		if m := alt.FindStringSubmatch(p.Version); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

// Parser converts Wiz container scan JSON into a Copacetic v1alpha1 UpdateManifest.
type Parser struct{}

// NewParser returns a Wiz report parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse reads a Wiz JSON report from path and returns an UpdateManifest.
func (p *Parser) Parse(file string) (*v1alpha1.UpdateManifest, error) {
	r, err := parseReport(file)
	if err != nil {
		return nil, err
	}

	osType, osVersion, arch := inferOSAndArch(r.Result.OSPackages)
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

	for i := range r.Result.OSPackages {
		pkg := &r.Result.OSPackages[i]
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

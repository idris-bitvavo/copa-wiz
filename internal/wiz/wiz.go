package wiz

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

type report struct {
	Result             *diskScanResult     `json:"result"`
	ScanOriginResource *scanOriginResource `json:"scanOriginResource"`
}

type scanOriginResource struct {
	Name string `json:"name"`
}

type diskScanResult struct {
	Typename                             string         `json:"__typename"`
	OSPackages                           []osPackage    `json:"osPackages"`
	VulnerableSBOMArtifactsByNameVersion []sbomArtifact `json:"vulnerableSBOMArtifactsByNameVersion"`
}

type sbomArtifact struct {
	Type *sbomType `json:"type"`
}

type sbomType struct {
	OSPackageManager string `json:"osPackageManager"`
}

type osPackage struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type vulnerability struct {
	Name         string `json:"name"`
	FixedVersion string `json:"fixedVersion"`
	Source       string `json:"source"`
}

const maxReportSizeBytes int64 = 25 * 1024 * 1024 // 25 MiB

func parseReport(path string) (rep *report, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close wiz report: %w", cerr)
		}
	}()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > maxReportSizeBytes {
		return nil, fmt.Errorf("wiz report too large: %d bytes exceeds max %d", st.Size(), maxReportSizeBytes)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxReportSizeBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxReportSizeBytes {
		return nil, fmt.Errorf("wiz report exceeds max size %d bytes", maxReportSizeBytes)
	}

	var r report
	if err = json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("wiz report JSON: %w", err)
	}
	if r.Result == nil {
		return nil, fmt.Errorf("wiz report: missing top-level \"result\"")
	}
	// Empty/null osPackages is valid: Copacetic only patches OS packages, so
	// library-only scans produce an empty UpdateManifest rather than an error.
	return &r, nil
}

// Parser converts Wiz container scan JSON into a Copacetic v1alpha1 UpdateManifest.
type Parser struct{}

// NewParser returns a Wiz report parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse reads a Wiz JSON report from path and returns an UpdateManifest.
//
// OS type/version are reconstructed to match Copacetic’s Trivy contract
// (metadata.os.type / metadata.os.version). Wiz rarely embeds /etc/os-release;
// detection uses the ordered distro probe registry in os_detect.go.
func (p *Parser) Parse(file string) (*v1alpha1.UpdateManifest, error) {
	r, err := parseReport(file)
	if err != nil {
		return nil, err
	}

	arch := "amd64"

	// Library-only / no OS package findings: succeed with an empty update list.
	if len(r.Result.OSPackages) == 0 {
		return &v1alpha1.UpdateManifest{
			APIVersion: v1alpha1.APIVersion,
			Metadata: v1alpha1.Metadata{
				OS:     v1alpha1.OS{},
				Config: v1alpha1.Config{Arch: arch},
			},
			Updates: []v1alpha1.UpdatePackage{},
		}, nil
	}

	osType, osVersion, arch := inferOSAndArch(r)
	if osType == "" {
		return nil, unsupportedOSError(r)
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
		Updates: []v1alpha1.UpdatePackage{},
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

	updates.Metadata.OS.Version = applyVersionDefaults(osType, updates.Metadata.OS.Version, len(updates.Updates))

	if err := requireReleaseWhenPatching(osType, updates.Metadata.OS.Version, len(updates.Updates)); err != nil {
		return nil, err
	}

	return &updates, nil
}

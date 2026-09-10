package wiz

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
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

var debReleaseRe = regexp.MustCompile(`deb(\d+)u`)
var debAltReleaseRe = regexp.MustCompile(`\+deb(\d+)`)
var apkVersionRe = regexp.MustCompile(`-r\d+$`)
var alpineImageTagRe = regexp.MustCompile(`(?i)(?:^|/)alpine:([0-9]+(?:\.[0-9]+)*)`)
var amznReleaseRe = regexp.MustCompile(`\.amzn(\d+)`)
var amazonLinuxImageTagRe = regexp.MustCompile(`(?i)(?:^|/)amazonlinux:([0-9]+)`)
var amazonCorrettoALRe = regexp.MustCompile(`(?i)\bal(\d{4})\b`)
var ubuntuTokenRe = regexp.MustCompile(`(?i)ubuntu`)
var ubuntuYYMMRe = regexp.MustCompile(`(?:^|[^0-9])(1[8-9]\.04|2[0-9]\.04)(?:[^0-9]|$)`)
var ubuntuImageTagRe = regexp.MustCompile(`(?i)(?:^|/)ubuntu:([0-9]+\.[0-9]+)`)
var elReleaseRe = regexp.MustCompile(`\.el([0-9]+)`)
var cmReleaseRe = regexp.MustCompile(`\.cm([0-9]+)`)
var azlReleaseRe = regexp.MustCompile(`\.azl([0-9]+)`)
var azureLinuxImageTagRe = regexp.MustCompile(`(?i)azurelinux[^:]*:([0-9]+(?:\.[0-9]+)?)`)

// Ubuntu image tags often use the series codename (e.g. jammy → 22.04).
var ubuntuCodenames = map[string]string{
	"bionic":   "18.04",
	"focal":    "20.04",
	"jammy":    "22.04",
	"noble":    "24.04",
	"oracular": "24.10",
	"plucky":   "25.04",
}

const maxReportSizeBytes int64 = 25 * 1024 * 1024 // 25 MiB

var supportedDistros = "debian, ubuntu, alpine, amazon, redhat, cbl-mariner, azurelinux"

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

func inferOSAndArch(r *report) (osType, osVersion, arch string) {
	arch = "amd64"
	pkgs := r.Result.OSPackages

	// Debian before Ubuntu: both are dpkg-family; debNNu/+debNN is Debian-specific.
	if debVer := inferDebianRelease(pkgs); debVer != "" {
		return "debian", debVer, arch
	}

	if isUbuntuReport(r) {
		return "ubuntu", inferUbuntuRelease(r), arch
	}

	if isAlpineReport(r) {
		return "alpine", inferAlpineRelease(r), arch
	}

	if isAmazonReport(r) {
		return "amazon", inferAmazonRelease(r), arch
	}

	// Azure Linux before CBL-Mariner: both are Microsoft RPM families.
	if isAzureLinuxReport(r) {
		return "azurelinux", inferAzureLinuxRelease(r), arch
	}

	if isMarinerReport(r) {
		return "cbl-mariner", inferMarinerRelease(r), arch
	}

	if isRedHatReport(r) {
		return "redhat", inferRedHatRelease(r), arch
	}

	return "", "", arch
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
	for _, p := range pkgs {
		if m := debAltReleaseRe.FindStringSubmatch(p.Version); len(m) == 2 {
			return m[1]
		}
		for _, v := range p.Vulnerabilities {
			if m := debAltReleaseRe.FindStringSubmatch(v.FixedVersion); len(m) == 2 {
				return m[1]
			}
		}
	}
	return ""
}

func isUbuntuReport(r *report) bool {
	if r == nil || r.Result == nil {
		return false
	}

	if r.ScanOriginResource != nil {
		lower := strings.ToLower(r.ScanOriginResource.Name)
		if strings.Contains(lower, "/ubuntu:") || strings.HasPrefix(lower, "ubuntu:") {
			return true
		}
		for code := range ubuntuCodenames {
			if strings.Contains(lower, code) {
				return true
			}
		}
	}

	for _, p := range r.Result.OSPackages {
		if ubuntuTokenRe.MatchString(p.Version) {
			return true
		}
		for _, v := range p.Vulnerabilities {
			if ubuntuTokenRe.MatchString(v.FixedVersion) {
				return true
			}
			if strings.Contains(strings.ToLower(v.Source), "ubuntu.com") {
				return true
			}
		}
	}
	return false
}

func inferUbuntuRelease(r *report) string {
	if r == nil || r.Result == nil {
		return ""
	}

	for _, p := range r.Result.OSPackages {
		if m := ubuntuYYMMRe.FindStringSubmatch(p.Version); len(m) == 2 {
			return m[1]
		}
		for _, v := range p.Vulnerabilities {
			if m := ubuntuYYMMRe.FindStringSubmatch(v.FixedVersion); len(m) == 2 {
				return m[1]
			}
		}
	}

	if r.ScanOriginResource != nil {
		name := r.ScanOriginResource.Name
		// Numeric tags such as ubuntu:22.04 before codename fallback.
		if m := ubuntuImageTagRe.FindStringSubmatch(name); len(m) == 2 {
			return m[1]
		}
		if m := ubuntuYYMMRe.FindStringSubmatch(name); len(m) == 2 {
			return m[1]
		}
		lower := strings.ToLower(name)
		for code, ver := range ubuntuCodenames {
			if strings.Contains(lower, code) {
				return ver
			}
		}
	}
	return ""
}

func isAlpineReport(r *report) bool {
	if r == nil || r.Result == nil {
		return false
	}

	for _, art := range r.Result.VulnerableSBOMArtifactsByNameVersion {
		if art.Type != nil && strings.EqualFold(art.Type.OSPackageManager, "APK") {
			return true
		}
	}

	if r.ScanOriginResource != nil {
		name := strings.ToLower(r.ScanOriginResource.Name)
		if strings.Contains(name, "/alpine:") || strings.HasPrefix(name, "alpine:") || strings.Contains(name, "/alpine@") {
			return true
		}
	}

	for _, p := range r.Result.OSPackages {
		if apkVersionRe.MatchString(p.Version) {
			return true
		}
		for _, v := range p.Vulnerabilities {
			if apkVersionRe.MatchString(v.FixedVersion) {
				return true
			}
			if strings.Contains(strings.ToLower(v.Source), "alpinelinux.org") {
				return true
			}
		}
	}

	return false
}

func inferAlpineRelease(r *report) string {
	if r != nil && r.ScanOriginResource != nil {
		if m := alpineImageTagRe.FindStringSubmatch(r.ScanOriginResource.Name); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

func isAmazonReport(r *report) bool {
	if r == nil || r.Result == nil {
		return false
	}

	if r.ScanOriginResource != nil {
		name := strings.ToLower(r.ScanOriginResource.Name)
		if strings.Contains(name, "amazonlinux") || strings.Contains(name, "amazoncorretto") {
			return true
		}
	}

	for _, p := range r.Result.OSPackages {
		if amznReleaseRe.MatchString(p.Version) {
			return true
		}
		for _, v := range p.Vulnerabilities {
			if amznReleaseRe.MatchString(v.FixedVersion) {
				return true
			}
			if strings.Contains(strings.ToLower(v.Source), "alas.aws.amazon.com") {
				return true
			}
		}
	}
	return false
}

func inferAmazonRelease(r *report) string {
	if r == nil || r.Result == nil {
		return ""
	}

	for _, p := range r.Result.OSPackages {
		if m := amznReleaseRe.FindStringSubmatch(p.Version); len(m) == 2 {
			return m[1]
		}
		for _, v := range p.Vulnerabilities {
			if m := amznReleaseRe.FindStringSubmatch(v.FixedVersion); len(m) == 2 {
				return m[1]
			}
		}
	}

	if r.ScanOriginResource != nil {
		name := r.ScanOriginResource.Name
		if m := amazonLinuxImageTagRe.FindStringSubmatch(name); len(m) == 2 {
			return m[1]
		}
		if m := amazonCorrettoALRe.FindStringSubmatch(name); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

func isAzureLinuxReport(r *report) bool {
	if r == nil || r.Result == nil {
		return false
	}

	if r.ScanOriginResource != nil {
		name := strings.ToLower(r.ScanOriginResource.Name)
		// Require a clear Azure Linux marker; avoid matching incidental "azure" substrings.
		if strings.Contains(name, "azurelinux") || strings.Contains(name, "azure-linux") {
			return true
		}
	}

	for _, p := range r.Result.OSPackages {
		if azlReleaseRe.MatchString(p.Version) {
			return true
		}
		for _, v := range p.Vulnerabilities {
			if azlReleaseRe.MatchString(v.FixedVersion) {
				return true
			}
			src := strings.ToLower(v.Source)
			if strings.Contains(src, "azurelinux") || strings.Contains(src, "azure-linux") {
				return true
			}
		}
	}
	return false
}

func inferAzureLinuxRelease(r *report) string {
	if r == nil || r.Result == nil {
		return ""
	}
	for _, p := range r.Result.OSPackages {
		if m := azlReleaseRe.FindStringSubmatch(p.Version); len(m) == 2 {
			return m[1] + ".0"
		}
		for _, v := range p.Vulnerabilities {
			if m := azlReleaseRe.FindStringSubmatch(v.FixedVersion); len(m) == 2 {
				return m[1] + ".0"
			}
		}
	}
	if r.ScanOriginResource != nil {
		if m := azureLinuxImageTagRe.FindStringSubmatch(r.ScanOriginResource.Name); len(m) == 2 {
			if !strings.Contains(m[1], ".") {
				return m[1] + ".0"
			}
			return m[1]
		}
	}
	return ""
}

func isMarinerReport(r *report) bool {
	if r == nil || r.Result == nil {
		return false
	}

	if r.ScanOriginResource != nil {
		name := strings.ToLower(r.ScanOriginResource.Name)
		// Mariner only — do not treat azurelinux images as cbl-mariner.
		if strings.Contains(name, "mariner") {
			return true
		}
	}

	for _, p := range r.Result.OSPackages {
		if cmReleaseRe.MatchString(p.Version) {
			return true
		}
		for _, v := range p.Vulnerabilities {
			if cmReleaseRe.MatchString(v.FixedVersion) {
				return true
			}
			src := strings.ToLower(v.Source)
			if strings.Contains(src, "cbl-mariner") {
				return true
			}
		}
	}
	return false
}

func inferMarinerRelease(r *report) string {
	if r == nil || r.Result == nil {
		return ""
	}
	for _, p := range r.Result.OSPackages {
		if m := cmReleaseRe.FindStringSubmatch(p.Version); len(m) == 2 {
			return m[1] + ".0"
		}
		for _, v := range p.Vulnerabilities {
			if m := cmReleaseRe.FindStringSubmatch(v.FixedVersion); len(m) == 2 {
				return m[1] + ".0"
			}
		}
	}
	return ""
}

func isRedHatReport(r *report) bool {
	if r == nil || r.Result == nil {
		return false
	}

	// .elN alone is shared by CentOS/Alma/Rocky — require RHEL-specific evidence.
	if r.ScanOriginResource != nil && hasRedHatImageMarker(r.ScanOriginResource.Name) {
		return true
	}

	for _, p := range r.Result.OSPackages {
		for _, v := range p.Vulnerabilities {
			if strings.Contains(strings.ToLower(v.Source), "access.redhat.com") {
				return true
			}
		}
	}
	return false
}

func hasRedHatImageMarker(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "redhat") ||
		strings.Contains(lower, "rhel") ||
		strings.Contains(lower, "/ubi") ||
		strings.Contains(lower, "ubi8") ||
		strings.Contains(lower, "ubi9") ||
		strings.Contains(lower, "ubi:")
}

func inferRedHatRelease(r *report) string {
	if r == nil || r.Result == nil {
		return ""
	}
	for _, p := range r.Result.OSPackages {
		if m := elReleaseRe.FindStringSubmatch(p.Version); len(m) == 2 {
			return m[1]
		}
		for _, v := range p.Vulnerabilities {
			if m := elReleaseRe.FindStringSubmatch(v.FixedVersion); len(m) == 2 {
				return m[1]
			}
		}
	}
	return ""
}

func packageManagers(r *report) []string {
	if r == nil || r.Result == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, art := range r.Result.VulnerableSBOMArtifactsByNameVersion {
		if art.Type == nil {
			continue
		}
		m := strings.TrimSpace(art.Type.OSPackageManager)
		if m == "" {
			continue
		}
		key := strings.ToUpper(m)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func unsupportedOSError(r *report) error {
	n := 0
	if r != nil && r.Result != nil {
		n = len(r.Result.OSPackages)
	}
	managers := packageManagers(r)
	if len(managers) > 0 {
		return fmt.Errorf("unsupported OS in report with %d osPackages (package managers: %s); supported: %s — extend wiz.go to handle this distro", n, strings.Join(managers, ", "), supportedDistros)
	}
	return fmt.Errorf("unsupported OS in report with %d osPackages (no matching version, source, or image markers); supported: %s — extend wiz.go to handle this distro", n, supportedDistros)
}

func requireReleaseWhenPatching(osType, osVersion string, updateCount int) error {
	if updateCount == 0 {
		// Nothing to patch — Copacetic will no-op; OS version is optional.
		return nil
	}
	switch osType {
	case "debian":
		if osVersion == "" {
			return fmt.Errorf("could not infer Debian release from package versions (expected patterns like deb12u1 in versions)")
		}
	case "ubuntu":
		if osVersion == "" {
			return fmt.Errorf("could not infer Ubuntu release (expected YY.04 in package versions, ubuntu:YY.04 image tags, or a codename like jammy)")
		}
	case "alpine":
		// Copacetic requires a non-empty OS version in report metadata before
		// GetPackageManager (patch/core.go), even though apk uses no tooling image.
		if osVersion == "" {
			return fmt.Errorf("could not infer Alpine release (expected alpine:X.Y or alpine:X.Y.Z in scanOriginResource image name)")
		}
	case "amazon":
		if osVersion == "" {
			return fmt.Errorf("could not infer Amazon Linux release (expected .amznYYYY in package versions or amazonlinux:/alYYYY image tags)")
		}
	case "redhat":
		if osVersion == "" {
			return fmt.Errorf("could not infer Red Hat Enterprise Linux release (expected .elN in package versions)")
		}
	case "cbl-mariner":
		if osVersion == "" {
			return fmt.Errorf("could not infer CBL-Mariner release (expected .cmN in package versions)")
		}
	case "azurelinux":
		if osVersion == "" {
			return fmt.Errorf("could not infer Azure Linux release (expected .azlN in package versions or azurelinux:N image tags)")
		}
	}
	return nil
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

	if err := requireReleaseWhenPatching(osType, osVersion, len(updates.Updates)); err != nil {
		return nil, err
	}

	return &updates, nil
}

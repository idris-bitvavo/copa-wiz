package wiz

import (
	"fmt"
	"regexp"
	"strings"
)

// Copacetic/Trivy-shaped OS identifiers we emit in UpdateManifest.metadata.os.
// Trivy fills these from /etc/os-release (etc.); Wiz reports usually do not, so we
// reconstruct the same contract from package versions, vuln sources, SBOM package
// managers, and image names.
const (
	osDebian     = "debian"
	osUbuntu     = "ubuntu"
	osAlpine     = "alpine"
	osAmazon     = "amazon"
	osRedHat     = "redhat"
	osMariner    = "cbl-mariner"
	osAzureLinux = "azurelinux"
)

// Alpine last-resort when updates exist but no series is in the image tag
// (e.g. amazoncorretto:17-alpine). Prefer an explicit alpine:X.Y / alpineX.Y tag.
const alpineVersionFallback = "3.20"

var supportedDistros = strings.Join([]string{
	osDebian, osUbuntu, osAlpine, osAmazon, osRedHat, osMariner, osAzureLinux,
}, ", ")

// distroProbe identifies a distro and extracts a Trivy-shaped version string.
// Probes run in order; first match wins (order encodes Debian-before-Ubuntu, etc.).
type distroProbe struct {
	Type    string
	Match   func(*report) bool
	Version func(*report) string
}

var (
	debReleaseRe    = regexp.MustCompile(`deb(\d+)u`)
	debAltReleaseRe = regexp.MustCompile(`\+deb(\d+)`)
	debianImageRe   = regexp.MustCompile(`(?i)(?:^|/)debian:([0-9]+(?:\.[0-9]+)?)`)
	baseFilesVerRe  = regexp.MustCompile(`^(\d+)(?:[.+]|$)`)

	apkVersionRe        = regexp.MustCompile(`-r\d+$`)
	alpineImageTagRe    = regexp.MustCompile(`(?i)(?:^|/)alpine:([0-9]+(?:\.[0-9]+)*)`)
	alpineEmbeddedTagRe = regexp.MustCompile(`(?i)alpine[_.:-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

	amznReleaseRe         = regexp.MustCompile(`\.amzn(\d+)`)
	amazonLinuxImageTagRe = regexp.MustCompile(`(?i)(?:^|/)amazonlinux:([0-9]+)`)
	amazonCorrettoALRe    = regexp.MustCompile(`(?i)\bal(\d{4})\b`)
	amazonALShortRe       = regexp.MustCompile(`(?i)(?:^|[^a-z])al(2|2022|2023)(?:[^0-9]|$)`)

	ubuntuTokenRe        = regexp.MustCompile(`(?i)ubuntu`)
	ubuntuYYMMRe         = regexp.MustCompile(`(?:^|[^0-9])(1[8-9]\.(?:04|10)|2[0-9]\.(?:04|10))(?:[^0-9]|$)`)
	ubuntuImageTagRe     = regexp.MustCompile(`(?i)(?:^|/)ubuntu:([0-9]+\.[0-9]+)`)
	ubuntuGlibcVersionRe = regexp.MustCompile(`^(2\.\d+)(?:-|$)`)

	elReleaseRe        = regexp.MustCompile(`\.el([0-9]+)`)
	ubiImageReleaseRe  = regexp.MustCompile(`(?i)\bubi([0-9]+)\b`)
	rhelImageReleaseRe = regexp.MustCompile(`(?i)(?:^|/)(?:rhel|redhat)[^:]*:([0-9]+)`)

	cmReleaseRe       = regexp.MustCompile(`\.cm([0-9]+)`)
	marinerImageTagRe = regexp.MustCompile(`(?i)(?:^|/)(?:cbl-)?mariner[^:]*:([0-9]+(?:\.[0-9]+)?)`)

	azlReleaseRe         = regexp.MustCompile(`\.azl([0-9]+)`)
	azureLinuxImageTagRe = regexp.MustCompile(`(?i)azurelinux[^:]*:([0-9]+(?:\.[0-9]+)?)`)
)

// Ubuntu DISTRIB_CODENAME → VERSION_ID (Trivy Name).
var ubuntuCodenames = map[string]string{
	"bionic":   "18.04",
	"cosmic":   "18.10",
	"disco":    "19.04",
	"eoan":     "19.10",
	"focal":    "20.04",
	"groovy":   "20.10",
	"hirsute":  "21.04",
	"impish":   "21.10",
	"jammy":    "22.04",
	"kinetic":  "22.10",
	"lunar":    "23.04",
	"mantic":   "23.10",
	"noble":    "24.04",
	"oracular": "24.10",
	"plucky":   "25.04",
	"questing": "25.10",
}

// glibc upstream shipped with each Ubuntu series (libc6 / libc-bin / locales).
var ubuntuGlibcToRelease = map[string]string{
	"2.27": "18.04",
	"2.28": "18.10",
	"2.29": "19.04",
	"2.30": "19.10",
	"2.31": "20.04",
	"2.32": "20.10",
	"2.33": "21.04",
	"2.34": "21.10",
	"2.35": "22.04",
	"2.36": "22.10",
	"2.37": "23.04",
	"2.38": "23.10",
	"2.39": "24.04",
	"2.40": "24.10",
	"2.41": "25.04",
}

// Ordered like Trivy’s merge rules: Debian markers beat Ubuntu; Azure before Mariner.
var distroProbes = []distroProbe{
	{Type: osDebian, Match: matchDebian, Version: versionDebian},
	{Type: osUbuntu, Match: matchUbuntu, Version: versionUbuntu},
	{Type: osAlpine, Match: matchAlpine, Version: versionAlpine},
	{Type: osAmazon, Match: matchAmazon, Version: versionAmazon},
	{Type: osAzureLinux, Match: matchAzureLinux, Version: versionAzureLinux},
	{Type: osMariner, Match: matchMariner, Version: versionMariner},
	{Type: osRedHat, Match: matchRedHat, Version: versionRedHat},
}

func inferOSAndArch(r *report) (osType, osVersion, arch string) {
	arch = "amd64"
	if r == nil || r.Result == nil {
		return "", "", arch
	}
	for _, p := range distroProbes {
		if !p.Match(r) {
			continue
		}
		ver := normalizeOSVersion(p.Type, p.Version(r))
		return p.Type, ver, arch
	}
	return "", "", arch
}

// normalizeOSVersion shapes versions to what Copacetic tooling expects
// (mirrors Trivy Metadata.OS.Name conventions used by pkgmgr).
func normalizeOSVersion(osType, version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	switch osType {
	case osDebian:
		if i := strings.IndexAny(version, "./-"); i > 0 {
			return version[:i]
		}
		return version
	case osUbuntu:
		if m := ubuntuYYMMRe.FindStringSubmatch(version); len(m) == 2 {
			return m[1]
		}
		return version
	case osAlpine:
		// Prefer X.Y or X.Y.Z; drop stray suffixes.
		if m := regexp.MustCompile(`^([0-9]+\.[0-9]+(?:\.[0-9]+)?)`).FindStringSubmatch(version); len(m) == 2 {
			return m[1]
		}
		return version
	case osAmazon:
		// Trivy detectors keep "2 (Karoo)" / "2023 (Amazon Linux)"; Copa is happier with bare major/year.
		fields := strings.Fields(version)
		if len(fields) > 0 {
			return fields[0]
		}
		return version
	case osMariner, osAzureLinux:
		if !strings.Contains(version, ".") {
			return version + ".0"
		}
		parts := strings.Split(version, ".")
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1]
		}
		return version
	case osRedHat:
		if i := strings.IndexAny(version, "./-"); i > 0 {
			return version[:i]
		}
		return version
	default:
		return version
	}
}

func applyVersionDefaults(osType, osVersion string, updateCount int) string {
	if osVersion != "" || updateCount == 0 {
		return osVersion
	}
	if osType == osAlpine {
		return alpineVersionFallback
	}
	return osVersion
}

func requireReleaseWhenPatching(osType, osVersion string, updateCount int) error {
	if updateCount == 0 || osVersion != "" {
		return nil
	}
	hints := map[string]string{
		osDebian:     "expected debNNu/+debNN in package versions or debian:N image tags",
		osUbuntu:     "expected YY.04 in package versions, libc6 glibc series, ubuntu:YY.04 / codename image tags",
		osAlpine:     "expected alpine:X.Y or alpineX.Y in the image name",
		osAmazon:     "expected .amznYYYY in package versions or amazonlinux:/alYYYY / al2023 image tags",
		osRedHat:     "expected .elN in package versions or ubiN / rhel:N image tags",
		osMariner:    "expected .cmN in package versions or mariner:N image tags",
		osAzureLinux: "expected .azlN in package versions or azurelinux:N image tags",
	}
	hint := hints[osType]
	if hint == "" {
		hint = "could not infer OS version"
	}
	return fmt.Errorf("could not infer %s release (%s)", osType, hint)
}

// --- shared signal helpers ---------------------------------------------------

func imageName(r *report) string {
	if r == nil || r.ScanOriginResource == nil {
		return ""
	}
	return r.ScanOriginResource.Name
}

func imageNameLower(r *report) string {
	return strings.ToLower(imageName(r))
}

func eachVersionString(r *report, fn func(string)) {
	if r == nil || r.Result == nil {
		return
	}
	for i := range r.Result.OSPackages {
		p := &r.Result.OSPackages[i]
		fn(p.Version)
		for j := range p.Vulnerabilities {
			fn(p.Vulnerabilities[j].FixedVersion)
		}
	}
}

func eachVulnSource(r *report, fn func(string)) {
	if r == nil || r.Result == nil {
		return
	}
	for i := range r.Result.OSPackages {
		for j := range r.Result.OSPackages[i].Vulnerabilities {
			fn(r.Result.OSPackages[i].Vulnerabilities[j].Source)
		}
	}
}

func hasPackageManager(r *report, want string) bool {
	if r == nil || r.Result == nil {
		return false
	}
	for _, art := range r.Result.VulnerableSBOMArtifactsByNameVersion {
		if art.Type != nil && strings.EqualFold(art.Type.OSPackageManager, want) {
			return true
		}
	}
	return false
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

func firstSubmatchFromVersions(r *report, re *regexp.Regexp) string {
	var found string
	eachVersionString(r, func(s string) {
		if found != "" || s == "" {
			return
		}
		if v := firstSubmatch(re, s); v != "" {
			found = v
		}
	})
	return found
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
		return fmt.Errorf("unsupported OS in report with %d osPackages (package managers: %s); supported: %s — extend os_detect.go to handle this distro", n, strings.Join(managers, ", "), supportedDistros)
	}
	return fmt.Errorf("unsupported OS in report with %d osPackages (no matching version, source, or image markers); supported: %s — extend os_detect.go to handle this distro", n, supportedDistros)
}

// --- Debian ------------------------------------------------------------------

func matchDebian(r *report) bool {
	if firstSubmatchFromVersions(r, debReleaseRe) != "" || firstSubmatchFromVersions(r, debAltReleaseRe) != "" {
		return true
	}
	name := imageNameLower(r)
	if strings.Contains(name, "/debian:") || strings.HasPrefix(name, "debian:") || strings.Contains(name, "/debian@") {
		return true
	}
	// base-files on Debian lacks an "ubuntu" token (Ubuntu's base-files versions usually include it).
	if r != nil && r.Result != nil {
		for _, p := range r.Result.OSPackages {
			if strings.EqualFold(p.Name, "base-files") &&
				baseFilesVerRe.MatchString(p.Version) &&
				!ubuntuTokenRe.MatchString(p.Version) {
				return true
			}
		}
	}
	return false
}

func versionDebian(r *report) string {
	if v := firstSubmatchFromVersions(r, debReleaseRe); v != "" {
		return v
	}
	if v := firstSubmatchFromVersions(r, debAltReleaseRe); v != "" {
		return v
	}
	if r.Result != nil {
		for _, p := range r.Result.OSPackages {
			if strings.EqualFold(p.Name, "base-files") {
				if v := firstSubmatch(baseFilesVerRe, p.Version); v != "" {
					return v
				}
			}
		}
	}
	if v := firstSubmatch(debianImageRe, imageName(r)); v != "" {
		return v
	}
	return ""
}

// --- Ubuntu ------------------------------------------------------------------

func matchUbuntu(r *report) bool {
	name := imageNameLower(r)
	if strings.Contains(name, "/ubuntu:") || strings.HasPrefix(name, "ubuntu:") {
		return true
	}
	for code := range ubuntuCodenames {
		if strings.Contains(name, code) {
			return true
		}
	}
	hit := false
	eachVersionString(r, func(s string) {
		if ubuntuTokenRe.MatchString(s) {
			hit = true
		}
	})
	if hit {
		return true
	}
	eachVulnSource(r, func(src string) {
		if strings.Contains(strings.ToLower(src), "ubuntu.com") {
			hit = true
		}
	})
	return hit
}

func versionUbuntu(r *report) string {
	if v := firstSubmatchFromVersions(r, ubuntuYYMMRe); v != "" {
		return v
	}
	if v := versionUbuntuFromGlibc(r); v != "" {
		return v
	}
	name := imageName(r)
	if v := firstSubmatch(ubuntuImageTagRe, name); v != "" {
		return v
	}
	if v := firstSubmatch(ubuntuYYMMRe, name); v != "" {
		return v
	}
	lower := strings.ToLower(name)
	for code, ver := range ubuntuCodenames {
		if strings.Contains(lower, code) {
			return ver
		}
	}
	return ""
}

func versionUbuntuFromGlibc(r *report) string {
	if r == nil || r.Result == nil {
		return ""
	}
	for _, p := range r.Result.OSPackages {
		switch strings.ToLower(p.Name) {
		case "libc6", "libc-bin", "locales", "libc6-dev":
			if m := ubuntuGlibcVersionRe.FindStringSubmatch(p.Version); len(m) == 2 {
				if ver, ok := ubuntuGlibcToRelease[m[1]]; ok {
					return ver
				}
			}
			for _, v := range p.Vulnerabilities {
				if m := ubuntuGlibcVersionRe.FindStringSubmatch(v.FixedVersion); len(m) == 2 {
					if ver, ok := ubuntuGlibcToRelease[m[1]]; ok {
						return ver
					}
				}
			}
		}
	}
	return ""
}

// --- Alpine ------------------------------------------------------------------

func matchAlpine(r *report) bool {
	if hasPackageManager(r, "APK") {
		return true
	}
	name := imageNameLower(r)
	if strings.Contains(name, "/alpine:") || strings.HasPrefix(name, "alpine:") ||
		strings.Contains(name, "/alpine@") || strings.Contains(name, "-alpine") ||
		strings.Contains(name, "_alpine") {
		return true
	}
	hit := false
	eachVersionString(r, func(s string) {
		if apkVersionRe.MatchString(s) {
			hit = true
		}
	})
	if hit {
		return true
	}
	eachVulnSource(r, func(src string) {
		if strings.Contains(strings.ToLower(src), "alpinelinux.org") {
			hit = true
		}
	})
	return hit
}

func versionAlpine(r *report) string {
	name := imageName(r)
	if v := firstSubmatch(alpineImageTagRe, name); v != "" {
		return v
	}
	if v := firstSubmatch(alpineEmbeddedTagRe, name); v != "" {
		return v
	}
	return ""
}

// --- Amazon ------------------------------------------------------------------

func matchAmazon(r *report) bool {
	name := imageNameLower(r)
	if strings.Contains(name, "amazonlinux") || strings.Contains(name, "amazoncorretto") ||
		amazonALShortRe.MatchString(name) {
		return true
	}
	if firstSubmatchFromVersions(r, amznReleaseRe) != "" {
		return true
	}
	hit := false
	eachVulnSource(r, func(src string) {
		if strings.Contains(strings.ToLower(src), "alas.aws.amazon.com") {
			hit = true
		}
	})
	return hit
}

func versionAmazon(r *report) string {
	if v := firstSubmatchFromVersions(r, amznReleaseRe); v != "" {
		return v
	}
	name := imageName(r)
	if v := firstSubmatch(amazonLinuxImageTagRe, name); v != "" {
		return v
	}
	if v := firstSubmatch(amazonCorrettoALRe, name); v != "" {
		return v
	}
	if v := firstSubmatch(amazonALShortRe, name); v != "" {
		return v
	}
	return ""
}

// --- Azure Linux -------------------------------------------------------------

func matchAzureLinux(r *report) bool {
	name := imageNameLower(r)
	if strings.Contains(name, "azurelinux") || strings.Contains(name, "azure-linux") {
		return true
	}
	if firstSubmatchFromVersions(r, azlReleaseRe) != "" {
		return true
	}
	hit := false
	eachVulnSource(r, func(src string) {
		s := strings.ToLower(src)
		if strings.Contains(s, "azurelinux") || strings.Contains(s, "azure-linux") {
			hit = true
		}
	})
	return hit
}

func versionAzureLinux(r *report) string {
	if v := firstSubmatchFromVersions(r, azlReleaseRe); v != "" {
		return v
	}
	if v := firstSubmatch(azureLinuxImageTagRe, imageName(r)); v != "" {
		return v
	}
	return ""
}

// --- CBL-Mariner -------------------------------------------------------------

func matchMariner(r *report) bool {
	name := imageNameLower(r)
	if strings.Contains(name, "mariner") && !strings.Contains(name, "azurelinux") {
		return true
	}
	if firstSubmatchFromVersions(r, cmReleaseRe) != "" {
		return true
	}
	hit := false
	eachVulnSource(r, func(src string) {
		if strings.Contains(strings.ToLower(src), "cbl-mariner") {
			hit = true
		}
	})
	return hit
}

func versionMariner(r *report) string {
	if v := firstSubmatchFromVersions(r, cmReleaseRe); v != "" {
		return v
	}
	if v := firstSubmatch(marinerImageTagRe, imageName(r)); v != "" {
		return v
	}
	return ""
}

// --- Red Hat -----------------------------------------------------------------

func matchRedHat(r *report) bool {
	if hasRedHatImageMarker(imageName(r)) {
		return true
	}
	hit := false
	eachVulnSource(r, func(src string) {
		if strings.Contains(strings.ToLower(src), "access.redhat.com") {
			hit = true
		}
	})
	return hit
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

func versionRedHat(r *report) string {
	if v := firstSubmatchFromVersions(r, elReleaseRe); v != "" {
		return v
	}
	name := imageName(r)
	if v := firstSubmatch(ubiImageReleaseRe, name); v != "" {
		return v
	}
	if v := firstSubmatch(rhelImageReleaseRe, name); v != "" {
		return v
	}
	return ""
}

package vulnr

import (
	"crypto/sha1"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/kyverno/kyverno/api/policyreport/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Severity = int

const (
	unknown Severity = iota
	low
	medium
	high
	critical
)

const (
	source       = "Trivy Vulnerability"
	reportPrefix = "trivy-vuln-polr"
	category     = "Vulnerability Scan"

	containerLabel = "trivy-operator.container.name"
	kindLabel      = "trivy-operator.resource.kind"
	nameLabel      = "trivy-operator.resource.name"
	namespaceLabel = "trivy-operator.resource.namespace"
)

var (
	reportLabels = map[string]string{
		"managed-by":            "trivy-operator-polr-adapter",
		"trivy-operator.source": "VulnerabilityReport",
	}
)

func Map(report *v1alpha1.VulnerabilityReport, polr *v1alpha2.PolicyReport) (*v1alpha2.PolicyReport, bool) {
	if len(report.Report.Vulnerabilities) == 0 {
		return nil, false
	}

	var updated bool

	if polr == nil {
		polr = CreatePolicyReport(report)
	} else {
		polr.Summary = CreateSummary(report.Report.Summary)
		polr.Results = []*v1alpha2.PolicyReportResult{}
		updated = true
	}

	res := CreateObjectReference(report)

	for _, vuln := range report.Report.Vulnerabilities {
		var score float64
		if vuln.Score != nil {
			score = *vuln.Score
		}

		result := MapResult(vuln.Severity)

		props := map[string]string{
			"artifact.repository": report.Report.Artifact.Repository,
			"artifact.tag":        report.Report.Artifact.Tag,
			"registry.server":     report.Report.Registry.Server,
			"score":               fmt.Sprint(score),
			"resource":            vuln.Resource,
			"resultID":            generateID(string(res.UID), res.Name, vuln.VulnerabilityID, vuln.Resource, string(result)),
		}

		if vuln.FixedVersion != "" {
			props["fixedVersion"] = vuln.FixedVersion
		}
		if vuln.InstalledVersion != "" {
			props["installedVersion"] = vuln.InstalledVersion
		}
		if vuln.PrimaryLink != "" {
			props["primaryLink"] = vuln.PrimaryLink
		}

		polr.Results = append(polr.Results, &v1alpha2.PolicyReportResult{
			Policy:     vuln.VulnerabilityID,
			Message:    vuln.Title,
			Properties: props,
			Resources:  []*corev1.ObjectReference{res},
			Result:     result,
			Severity:   MapServerity(vuln.Severity),
			Category:   category,
			Timestamp:  *report.CreationTimestamp.ProtoTime(),
			Source:     source,
		})
	}

	return polr, updated
}

func MapResult(severity v1alpha1.Severity) v1alpha2.PolicyResult {
	if severity == v1alpha1.SeverityUnknown || severity == v1alpha1.SeverityNone {
		return v1alpha2.StatusSkip
	} else if severity == v1alpha1.SeverityLow {
		return v1alpha2.StatusWarn
	} else if severity == v1alpha1.SeverityMedium {
		return v1alpha2.StatusWarn
	}

	return v1alpha2.StatusFail
}

func MapServerity(severity v1alpha1.Severity) v1alpha2.PolicySeverity {
	if severity == v1alpha1.SeverityUnknown || severity == v1alpha1.SeverityNone {
		return ""
	} else if severity == v1alpha1.SeverityLow {
		return v1alpha2.SeverityLow
	} else if severity == v1alpha1.SeverityMedium {
		return v1alpha2.SeverityMedium
	}

	return v1alpha2.SeverityHigh
}

func CreateObjectReference(report *v1alpha1.VulnerabilityReport) *corev1.ObjectReference {
	if len(report.OwnerReferences) == 1 {
		ref := report.OwnerReferences[0].DeepCopy()

		return &corev1.ObjectReference{
			Namespace:  report.Namespace,
			APIVersion: ref.APIVersion,
			Kind:       ref.Kind,
			Name:       ref.Name,
			UID:        ref.UID,
		}
	}
	return &corev1.ObjectReference{
		Namespace: report.Labels[namespaceLabel],
		Kind:      report.Labels[kindLabel],
		Name:      report.Labels[nameLabel],
	}
}

func CreatePolicyReport(report *v1alpha1.VulnerabilityReport) *v1alpha2.PolicyReport {
	return &v1alpha2.PolicyReport{
		ObjectMeta: v1.ObjectMeta{
			Name:            GeneratePolicyReportName(report),
			Namespace:       report.Namespace,
			Labels:          reportLabels,
			OwnerReferences: report.OwnerReferences,
		},
		Summary: CreateSummary(report.Report.Summary),
		Results: []*v1alpha2.PolicyReportResult{},
	}
}

func CreateSummary(sum v1alpha1.VulnerabilitySummary) v1alpha2.PolicyReportSummary {
	return v1alpha2.PolicyReportSummary{
		Skip: sum.UnknownCount + sum.NoneCount,
		Warn: sum.LowCount + sum.MediumCount,
		Fail: sum.HighCount + sum.CriticalCount,
	}
}

func GeneratePolicyReportName(report *v1alpha1.VulnerabilityReport) string {
	name := report.Name
	if len(report.OwnerReferences) == 1 {
		name = report.OwnerReferences[0].Name
	}

	return fmt.Sprintf("%s-%s", reportPrefix, name)
}

func generateID(uid, name, policy, rule, result string) string {
	id := fmt.Sprintf("%s_%s_%s_%s_%s", uid, name, policy, rule, result)

	h := sha1.New()
	h.Write([]byte(id))

	return fmt.Sprintf("%x", h.Sum(nil))
}

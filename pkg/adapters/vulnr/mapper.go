package vulnr

import (
	"crypto/sha1"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/policyreport/v1alpha2"
)

const (
	trivySource  = "Trivy Vulnerability"
	reportPrefix = "trivy-vuln-polr"
	category     = "Vulnerability Scan"

	containerLabel = "trivy-operator.container.name"
	kindLabel      = "trivy-operator.resource.kind"
	nameLabel      = "trivy-operator.resource.name"
	namespaceLabel = "trivy-operator.resource.namespace"
)

var reportLabels = map[string]string{
	"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
	"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
	"trivy-operator.source":        "VulnerabilityReport",
}

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.VulnerabilityReport, polr *v1alpha2.PolicyReport) (*v1alpha2.PolicyReport, bool) {
	if len(report.Report.Vulnerabilities) == 0 {
		return nil, false
	}

	var updated bool

	if polr == nil {
		polr = m.CreatePolicyReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, reportLabels)
		polr.Summary = CreateSummary(report.Report.Summary)
		polr.Results = []v1alpha2.PolicyReportResult{}
		updated = true
	}

	res := CreateObjectReference(report)

	polr.Scope = &res

	duplCache := map[string]bool{}

	for _, vuln := range report.Report.Vulnerabilities {
		result := shared.MapResult(vuln.Severity)
		id := generateID(string(res.UID), res.Name, vuln.VulnerabilityID, vuln.Resource, string(result))
		if duplCache[id] {
			continue
		}

		var score float64
		if vuln.Score != nil {
			score = *vuln.Score
		}

		props := map[string]string{
			"artifact.repository": report.Report.Artifact.Repository,
			"artifact.tag":        report.Report.Artifact.Tag,
			"registry.server":     report.Report.Registry.Server,
			"score":               fmt.Sprint(score),
			"resource":            vuln.Resource,
			"resultID":            id,
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

		if report.Report.OS.Family != "" {
			props["OS"] = strings.TrimSpace(fmt.Sprintf("%s %s", report.Report.OS.Family, report.Report.OS.Name))
		}

		for source, cvss := range vuln.CVSS {
			if cvss.V2Score != 0 {
				props[fmt.Sprintf("%s.v2_score", source)] = fmt.Sprint(cvss.V2Score)
			}
			if cvss.V2Vector != "" {
				props[fmt.Sprintf("%s.v2_vector", source)] = cvss.V2Vector
			}

			if cvss.V3Score != 0 {
				props[fmt.Sprintf("%s.v3_score", source)] = fmt.Sprint(cvss.V3Score)
			}
			if cvss.V3Vector != "" {
				props[fmt.Sprintf("%s.v3_vector", source)] = cvss.V3Vector
			}
		}

		polr.Results = append(polr.Results, v1alpha2.PolicyReportResult{
			Policy:     vuln.VulnerabilityID,
			Message:    vuln.Title,
			Properties: props,
			Result:     result,
			Severity:   shared.MapServerity(vuln.Severity),
			Category:   category,
			Timestamp:  *report.CreationTimestamp.ProtoTime(),
			Source:     trivySource,
		})

		duplCache[id] = true
	}

	return polr, updated
}

func CreateObjectReference(report *v1alpha1.VulnerabilityReport) corev1.ObjectReference {
	if len(report.OwnerReferences) == 1 {
		ref := report.OwnerReferences[0].DeepCopy()

		return corev1.ObjectReference{
			Namespace:  report.Namespace,
			APIVersion: ref.APIVersion,
			Kind:       ref.Kind,
			Name:       ref.Name,
			UID:        ref.UID,
		}
	}
	return corev1.ObjectReference{
		Namespace: report.Labels[namespaceLabel],
		Kind:      report.Labels[kindLabel],
		Name:      report.Labels[nameLabel],
	}
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.VulnerabilityReport) *v1alpha2.PolicyReport {
	return &v1alpha2.PolicyReport{
		ObjectMeta: v1.ObjectMeta{
			Name:            GeneratePolicyReportName(report),
			Namespace:       report.Namespace,
			Labels:          m.CreateLabels(report.Labels, reportLabels),
			OwnerReferences: report.OwnerReferences,
		},
		Summary: CreateSummary(report.Report.Summary),
		Results: []v1alpha2.PolicyReportResult{},
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
		name = fmt.Sprintf("%s-%s", strings.ToLower(report.OwnerReferences[0].Kind), report.OwnerReferences[0].Name)
	}

	return fmt.Sprintf("%s-%s", reportPrefix, name)
}

func generateID(uid, name, policy, rule, result string) string {
	id := fmt.Sprintf("%s_%s_%s_%s_%s", uid, name, policy, rule, result)

	h := sha1.New()
	h.Write([]byte(id))

	return fmt.Sprintf("%x", h.Sum(nil))
}

package openreports

import (
	"fmt"
	"strings"

	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/clustervulnr"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.ClusterVulnerabilityReport, polr *orv1alpha1.ClusterReport) (*orv1alpha1.ClusterReport, bool) {
	if len(report.Report.Vulnerabilities) == 0 {
		return nil, false
	}

	var updated bool

	if polr == nil {
		polr = m.CreateReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, clustervulnr.ReportLabels)
		polr.Summary = CreateSummary(report.Report.Summary)
		polr.Results = []orv1alpha1.ReportResult{}
		updated = true
	}

	res := CreateObjectReference(report)
	polr.Scope = &res

	duplCache := map[string]bool{}

	for _, vuln := range report.Report.Vulnerabilities {
		result := shared.MapORResult(vuln.Severity)
		id := clustervulnr.GenerateID(string(res.UID), res.Name, vuln.VulnerabilityID, vuln.Resource, string(result))
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

		if report.Report.OS.Family != "" {
			props["OS"] = strings.TrimSpace(fmt.Sprintf("%s %s", report.Report.OS.Family, report.Report.OS.Name))
		}

		polr.Results = append(polr.Results, orv1alpha1.ReportResult{
			Policy:      vuln.VulnerabilityID,
			Description: vuln.Title,
			Properties:  props,
			Result:      result,
			Severity:    shared.MapORServerity(vuln.Severity),
			Category:    clustervulnr.Category,
			Timestamp:   *report.CreationTimestamp.ProtoTime(),
			Source:      clustervulnr.TrivySource,
		})

		duplCache[id] = true
	}

	return polr, updated
}

func CreateObjectReference(report *v1alpha1.ClusterVulnerabilityReport) corev1.ObjectReference {
	if len(report.OwnerReferences) == 1 {
		ref := report.OwnerReferences[0].DeepCopy()

		return corev1.ObjectReference{
			APIVersion: ref.APIVersion,
			Kind:       ref.Kind,
			Name:       ref.Name,
			UID:        ref.UID,
		}
	}
	return corev1.ObjectReference{
		Kind: report.Labels[clustervulnr.KindLabel],
		Name: report.Labels[clustervulnr.NameLabel],
	}
}

func (m *mapper) CreateReport(report *v1alpha1.ClusterVulnerabilityReport) *orv1alpha1.ClusterReport {
	return &orv1alpha1.ClusterReport{
		ObjectMeta: v1.ObjectMeta{
			Name:            clustervulnr.GeneratePolicyReportName(report),
			Labels:          m.CreateLabels(report.Labels, clustervulnr.ReportLabels),
			OwnerReferences: report.OwnerReferences,
		},
		Source:  clustervulnr.TrivySource,
		Summary: CreateSummary(report.Report.Summary),
		Results: make([]orv1alpha1.ReportResult, 0),
	}
}

func CreateSummary(sum v1alpha1.VulnerabilitySummary) orv1alpha1.ReportSummary {
	return orv1alpha1.ReportSummary{
		Skip: sum.UnknownCount + sum.NoneCount,
		Warn: sum.LowCount + sum.MediumCount,
		Fail: sum.HighCount + sum.CriticalCount,
	}
}

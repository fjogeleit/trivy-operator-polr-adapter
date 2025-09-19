package openreports

import (
	"fmt"
	"strings"

	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/vulnr"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.VulnerabilityReport, polr *orv1alpha1.Report) (*orv1alpha1.Report, bool) {
	if len(report.Report.Vulnerabilities) == 0 {
		return nil, false
	}

	var updated bool

	if polr == nil {
		polr = m.CreateReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, vulnr.ReportLabels)
		polr.Summary = CreateSummary(report.Report.Summary)
		polr.Results = make([]orv1alpha1.ReportResult, 0)
		updated = true
	}

	res := vulnr.CreateObjectReference(report)

	polr.Scope = &res

	duplCache := map[string]bool{}

	for _, vuln := range report.Report.Vulnerabilities {
		result := shared.MapORResult(vuln.Severity)
		id := vulnr.GenerateID(string(res.UID), res.Name, vuln.VulnerabilityID, vuln.Resource, string(result))
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

		polr.Results = append(polr.Results, orv1alpha1.ReportResult{
			Policy:      vuln.VulnerabilityID,
			Description: vuln.Title,
			Properties:  props,
			Result:      result,
			Severity:    shared.MapORServerity(vuln.Severity),
			Category:    vulnr.Category,
			Timestamp:   *report.CreationTimestamp.ProtoTime(),
			Source:      vulnr.TrivySource,
		})

		duplCache[id] = true
	}

	return polr, updated
}

func (m *mapper) CreateReport(report *v1alpha1.VulnerabilityReport) *orv1alpha1.Report {
	return &orv1alpha1.Report{
		ObjectMeta: v1.ObjectMeta{
			Name:            vulnr.GeneratePolicyReportName(report),
			Namespace:       report.Namespace,
			Labels:          m.CreateLabels(report.Labels, vulnr.ReportLabels),
			OwnerReferences: report.OwnerReferences,
		},
		Source:  vulnr.TrivySource,
		Summary: CreateSummary(report.Report.Summary),
		Results: []orv1alpha1.ReportResult{},
	}
}

func CreateSummary(sum v1alpha1.VulnerabilitySummary) orv1alpha1.ReportSummary {
	return orv1alpha1.ReportSummary{
		Skip: sum.UnknownCount + sum.NoneCount,
		Warn: sum.LowCount + sum.MediumCount,
		Fail: sum.HighCount + sum.CriticalCount,
	}
}

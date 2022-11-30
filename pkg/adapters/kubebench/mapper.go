package kubebench

import (
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/kyverno/kyverno/api/policyreport/v1alpha2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	StatusFail = "FAIL"
	StatusWarn = "WARN"
	StatusInfo = "INFO"
	StatusPass = "PASS"
)

const (
	trivySource  = "CIS Kube Bench"
	reportPrefix = "cis-kube-bench-cpolr"
)

var (
	reportLabels = map[string]string{
		"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
		"trivy-operator.source":        "CISKubeBenchReport",
	}
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.CISKubeBenchReport, polr *v1alpha2.ClusterPolicyReport) (*v1alpha2.ClusterPolicyReport, bool) {
	var updated bool

	if polr == nil {
		polr = m.CreatePolicyReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, reportLabels)
		polr.Summary = v1alpha2.PolicyReportSummary{}
		polr.Results = []v1alpha2.PolicyReportResult{}
		updated = true
	}

	for _, section := range report.Report.Sections {
		for _, test := range section.Tests {
			for _, result := range test.Results {
				switch result.Status {
				case StatusFail:
					polr.Summary.Fail++
				case StatusPass:
					polr.Summary.Pass++
				case StatusWarn:
					polr.Summary.Warn++
				case StatusInfo:
					polr.Summary.Skip++
				}

				polr.Results = append(polr.Results, v1alpha2.PolicyReportResult{
					Policy:    fmt.Sprintf("%s %s", test.Section, test.Desc),
					Rule:      fmt.Sprintf("%s %s", result.TestNumber, result.TestDesc),
					Message:   result.Remediation,
					Scored:    result.Scored,
					Result:    MapResult(result.Status),
					Category:  section.Text,
					Timestamp: *report.CreationTimestamp.ProtoTime(),
					Source:    trivySource,
				})
			}
		}
	}

	return polr, updated
}

func MapResult(status string) v1alpha2.PolicyResult {
	switch status {
	case StatusFail:
		return v1alpha2.StatusFail
	case StatusPass:
		return v1alpha2.StatusPass
	case StatusWarn:
		return v1alpha2.StatusWarn
	}

	return v1alpha2.StatusSkip
}

func MapServerity(severity v1alpha1.Severity) v1alpha2.PolicySeverity {
	if severity == v1alpha1.SeverityUnknown || severity == v1alpha1.SeverityNone {
		return ""
	} else if severity == v1alpha1.SeverityLow {
		return v1alpha2.SeverityLow
	} else if severity == v1alpha1.SeverityMedium {
		return v1alpha2.SeverityMedium
	} else if severity == v1alpha1.SeverityHigh {
		return v1alpha2.SeverityHigh
	} else if severity == v1alpha1.SeverityCritical {
		return v1alpha2.SeverityCritical
	}

	return v1alpha2.SeverityInfo
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.CISKubeBenchReport) *v1alpha2.ClusterPolicyReport {
	return &v1alpha2.ClusterPolicyReport{
		ObjectMeta: v1.ObjectMeta{
			Name:      GeneratePolicyReportName(report.Name),
			Namespace: report.Namespace,
			Labels:    m.CreateLabels(report.Labels, reportLabels),
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: report.APIVersion,
					Kind:       report.Kind,
					Name:       report.Name,
					UID:        report.UID,
				},
			},
		},
		Summary: v1alpha2.PolicyReportSummary{},
		Results: []v1alpha2.PolicyReportResult{},
	}
}

func GeneratePolicyReportName(name string) string {
	return fmt.Sprintf("%s-%s", reportPrefix, name)
}

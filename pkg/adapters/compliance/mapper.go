package compliance

import (
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/kyverno/kyverno/api/policyreport/v1alpha2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	trivySource  = "Trivy Compliance"
	reportPrefix = "trivy-compliance-cpolr"
)

var (
	reportLabels = map[string]string{
		"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
		"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
		"trivy-operator.source":        "ClusterComplianceReport",
	}
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.ClusterComplianceReport, polr *v1alpha2.ClusterPolicyReport) (*v1alpha2.ClusterPolicyReport, bool) {
	var updated bool

	if polr == nil {
		polr = m.CreatePolicyReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, reportLabels)
		polr.Summary = v1alpha2.PolicyReportSummary{}
		polr.Results = []v1alpha2.PolicyReportResult{}
		updated = true
	}

	if report.Status.DetailReport == nil {
		return polr, updated
	}

	for _, result := range report.Status.DetailReport.Results {
		for _, check := range result.Checks {
			props := map[string]string{}

			if check.Target != "" {
				props["target"] = check.Target
			}

			if check.Remediation != "" {
				props["remediation"] = check.Remediation
			}

			if check.ID != "" {
				props["id"] = check.ID
			}

			var message string

			if len(check.Messages) == 1 {
				message = check.Messages[0]

				if message != check.Description {
					props["description"] = check.Description
				}
			} else if len(check.Messages) > 1 {
				var index int
				for _, msg := range check.Messages {
					if msg == "" {
						continue
					}
					index++
					props[fmt.Sprintf("%d. message", index)] = msg
				}

				message = check.Description
			}

			if check.Success {
				polr.Summary.Pass++
			} else {
				polr.Summary.Fail++
			}

			polr.Results = append(polr.Results, v1alpha2.PolicyReportResult{
				Policy:     fmt.Sprintf("%s %s", result.ID, result.Name),
				Category:   check.Category,
				Rule:       check.Title,
				Message:    message,
				Result:     MapResult(check.Success),
				Severity:   shared.MapServerity(check.Severity),
				Timestamp:  *report.CreationTimestamp.ProtoTime(),
				Source:     trivySource,
				Properties: props,
			})
		}
	}

	return polr, updated
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.ClusterComplianceReport) *v1alpha2.ClusterPolicyReport {
	return &v1alpha2.ClusterPolicyReport{
		ObjectMeta: v1.ObjectMeta{
			Name:   GeneratePolicyReportName(report.Name),
			Labels: m.CreateLabels(report.Labels, reportLabels),
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

func MapResult(success bool) v1alpha2.PolicyResult {
	if success {
		return v1alpha2.StatusPass
	}

	return v1alpha2.StatusFail
}

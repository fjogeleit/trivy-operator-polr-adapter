package infra

import (
	"fmt"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/policyreport/v1alpha2"
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.InfraAssessmentReport, polr *v1alpha2.PolicyReport) (*v1alpha2.PolicyReport, bool) {
	var updated bool

	if polr == nil {
		polr = m.CreatePolicyReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, ReportLabels)
		polr.Summary = v1alpha2.PolicyReportSummary{}
		polr.Results = []v1alpha2.PolicyReportResult{}
		updated = true
	}

	polr.Scope = shared.CreateObjectReference(report.Namespace, report.OwnerReferences, report.Labels)

	for _, check := range report.Report.Checks {
		props := map[string]string{}

		if check.Remediation != "" {
			props["remediation"] = check.Remediation
		}

		var message string

		if len(check.Messages) == 1 && check.Messages[0] != "" {
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
		} else {
			message = check.Description
		}

		if check.Success {
			polr.Summary.Pass++
		} else {
			polr.Summary.Fail++
		}

		polr.Results = append(polr.Results, v1alpha2.PolicyReportResult{
			Policy:     check.ID,
			Category:   check.Category,
			Rule:       check.Title,
			Message:    message,
			Result:     MapResult(check.Success),
			Severity:   shared.MapServerity(check.Severity),
			Timestamp:  *report.CreationTimestamp.ProtoTime(),
			Source:     TrivySource,
			Properties: props,
		})
	}

	return polr, updated
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.InfraAssessmentReport) *v1alpha2.PolicyReport {
	polr := &v1alpha2.PolicyReport{
		ObjectMeta: v1.ObjectMeta{
			Name:      GenerateReportName(report.Name),
			Namespace: report.Namespace,
			Labels:    m.CreateLabels(report.Labels, ReportLabels),
		},
		Summary: v1alpha2.PolicyReportSummary{},
		Results: []v1alpha2.PolicyReportResult{},
	}

	if report.UID != "" {
		polr.ObjectMeta.OwnerReferences = []v1.OwnerReference{
			{
				APIVersion: shared.APIVersion,
				Kind:       "InfraAssessmentReport",
				Name:       report.Name,
				UID:        report.UID,
			},
		}
	}

	return polr
}

func GenerateReportName(name string) string {
	return fmt.Sprintf("%s-%s", ReportPrefix, name)
}

func MapResult(success bool) v1alpha2.PolicyResult {
	if success {
		return v1alpha2.StatusPass
	}

	return v1alpha2.StatusFail
}

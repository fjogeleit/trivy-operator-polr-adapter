package openreports

import (
	"fmt"

	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/compliance"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/policyreport/v1alpha2"
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.ClusterComplianceReport, polr *orv1alpha1.ClusterReport) (*orv1alpha1.ClusterReport, bool) {
	var updated bool

	if polr == nil {
		polr = m.CreatePolicyReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, compliance.ReportLabels)
		polr.Summary = orv1alpha1.ReportSummary{}
		polr.Results = []orv1alpha1.ReportResult{}
		updated = true
	}

	if report.Status.DetailReport == nil {
		return polr, updated
	}

	for _, result := range report.Status.DetailReport.Results {
		for _, check := range result.Checks {
			status := MapResult(check.Success)

			props := map[string]string{
				"resultID": compliance.GenerateID(check.Target, result.Name, check.Title, check.Category, v1alpha2.PolicyResult(status)),
			}

			if check.Remediation != "" {
				props["remediation"] = check.Remediation
			}

			if check.ID != "" {
				props["id"] = check.ID
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

			if message == "" {
				message = result.Description
			}

			if check.Success {
				polr.Summary.Pass++
			} else {
				polr.Summary.Fail++
			}

			resources := []corev1.ObjectReference{}
			if check.Target != "" {
				resources = append(resources, corev1.ObjectReference{
					Name: check.Target,
				})
			}

			polr.Results = append(polr.Results, orv1alpha1.ReportResult{
				Policy:      fmt.Sprintf("%s %s", result.ID, result.Name),
				Category:    check.Category,
				Rule:        check.Title,
				Description: message,
				Result:      status,
				Severity:    shared.MapORServerity(check.Severity),
				Timestamp:   *report.CreationTimestamp.ProtoTime(),
				Source:      compliance.TrivySource,
				Properties:  props,
				Subjects:    resources,
			})
		}
	}

	return polr, updated
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.ClusterComplianceReport) *orv1alpha1.ClusterReport {
	cpolr := &orv1alpha1.ClusterReport{
		ObjectMeta: v1.ObjectMeta{
			Name:   compliance.GenerateReportName(report.Name),
			Labels: m.CreateLabels(report.Labels, compliance.ReportLabels),
		},
		Source:  compliance.TrivySource,
		Summary: orv1alpha1.ReportSummary{},
		Results: []orv1alpha1.ReportResult{},
	}

	if report.UID != "" {
		cpolr.ObjectMeta.OwnerReferences = []v1.OwnerReference{
			{
				APIVersion: shared.APIVersion,
				Kind:       "ClusterComplianceReport",
				Name:       report.Name,
				UID:        report.UID,
			},
		}
	}

	return cpolr
}

func MapResult(success bool) orv1alpha1.Result {
	if success {
		return v1alpha2.StatusPass
	}

	return v1alpha2.StatusFail
}

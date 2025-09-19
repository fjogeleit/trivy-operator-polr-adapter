package openreports

import (
	"fmt"

	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/auditr"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/policyreport/v1alpha2"
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.ConfigAuditReport, polr *orv1alpha1.Report) (*orv1alpha1.Report, bool) {
	if len(report.Report.Checks) == 0 {
		return nil, false
	}

	var updated bool

	if polr == nil {
		polr = m.CreatePolicyReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, auditr.ReportLabels)
		polr.Summary = orv1alpha1.ReportSummary{}
		polr.Results = []orv1alpha1.ReportResult{}
		updated = true
	}

	polr.Scope = shared.CreateObjectReference(report.Namespace, report.OwnerReferences, report.Labels)

	for _, check := range report.Report.Checks {
		props := map[string]string{}

		messages := []string{}
		for _, m := range check.Messages {
			if m == "" {
				continue
			}

			messages = append(messages, m)
		}

		if check.Success {
			polr.Summary.Pass++
		} else {
			polr.Summary.Fail++
		}

		message := check.Description
		if len(messages) == 1 {
			message = messages[0]

			props["description"] = check.Description
		} else {
			for index, msg := range messages {
				props[fmt.Sprintf("%d. message", index)] = msg
			}
		}

		polr.Results = append(polr.Results, orv1alpha1.ReportResult{
			Policy:      check.Title,
			Rule:        check.ID,
			Description: message,
			Properties:  props,
			Result:      MapResult(check.Success),
			Severity:    shared.MapORServerity(check.Severity),
			Category:    check.Category,
			Timestamp:   *report.CreationTimestamp.ProtoTime(),
			Source:      auditr.TrivySource,
		})
	}

	return polr, updated
}

func MapResult(success bool) orv1alpha1.Result {
	if success {
		return v1alpha2.StatusPass
	}

	return v1alpha2.StatusFail
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.ConfigAuditReport) *orv1alpha1.Report {
	return &orv1alpha1.Report{
		ObjectMeta: v1.ObjectMeta{
			Name:            auditr.GenerateReportName(report),
			Namespace:       report.Namespace,
			Labels:          m.CreateLabels(report.Labels, auditr.ReportLabels),
			OwnerReferences: report.OwnerReferences,
		},
		Source:  auditr.TrivySource,
		Summary: orv1alpha1.ReportSummary{},
		Results: []orv1alpha1.ReportResult{},
	}
}

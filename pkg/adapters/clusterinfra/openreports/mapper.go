package clusterinfra

import (
	"fmt"
	"strings"

	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/clusterinfra"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/policyreport/v1alpha2"
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.ClusterInfraAssessmentReport, polr *orv1alpha1.ClusterReport) (*orv1alpha1.ClusterReport, bool) {
	var updated bool

	if polr == nil {
		polr = m.CreateReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, clusterinfra.ReportLabels)
		polr.Summary = orv1alpha1.ReportSummary{}
		polr.Results = []orv1alpha1.ReportResult{}
		updated = true
	}

	polr.Scope = shared.CreateObjectReference(report.Namespace, report.OwnerReferences, report.Labels)

	for _, check := range report.Report.Checks {
		props := map[string]string{}

		if check.Remediation != "" {
			props["remediation"] = check.Remediation
		}

		var message string

		if len(check.Messages) == 1 && check.Messages[0] != "" && strings.Contains(check.Description, check.Messages[0]) {
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

		polr.Results = append(polr.Results, orv1alpha1.ReportResult{
			Policy:      check.ID,
			Category:    check.Category,
			Rule:        check.Title,
			Description: message,
			Result:      MapResult(check.Success),
			Severity:    shared.MapORServerity(check.Severity),
			Timestamp:   *report.CreationTimestamp.ProtoTime(),
			Source:      clusterinfra.TrivySource,
			Properties:  props,
		})
	}

	return polr, updated
}

func (m *mapper) CreateReport(report *v1alpha1.ClusterInfraAssessmentReport) *orv1alpha1.ClusterReport {
	cpolr := &orv1alpha1.ClusterReport{
		ObjectMeta: v1.ObjectMeta{
			Name:      clusterinfra.GenerateReportName(report.Name),
			Namespace: report.Namespace,
			Labels:    m.CreateLabels(report.Labels, clusterinfra.ReportLabels),
		},
		Source:  clusterinfra.TrivySource,
		Summary: orv1alpha1.ReportSummary{},
		Results: []orv1alpha1.ReportResult{},
	}

	if report.UID != "" {
		cpolr.ObjectMeta.OwnerReferences = []v1.OwnerReference{
			{
				APIVersion: shared.APIVersion,
				Kind:       "ClusterInfraAssessmentReport",
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

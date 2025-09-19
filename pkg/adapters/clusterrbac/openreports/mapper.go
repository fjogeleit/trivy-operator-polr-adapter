package openreports

import (
	"fmt"

	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/clusterrbac"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/policyreport/v1alpha2"
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.ClusterRbacAssessmentReport, polr *orv1alpha1.ClusterReport) (*orv1alpha1.ClusterReport, bool) {
	if len(report.Report.Checks) == 0 {
		return nil, false
	}

	var updated bool

	if polr == nil {
		polr = m.CreateReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, clusterrbac.ReportLabels)
		polr.Summary = CreateSummary(report)
		polr.Results = []orv1alpha1.ReportResult{}
		updated = true
	}

	polr.Scope = CreateObjectReference(report)

	for _, check := range report.Report.Checks {

		result := MapResult(check.Success)

		props := map[string]string{
			"resultID": clusterrbac.GenerateID(string(polr.Scope.UID), polr.Scope.Name, check.Title, check.ID, string(result)),
		}

		var index int
		for _, msg := range check.Messages {
			if msg == "" {
				continue
			}
			index++
			props[fmt.Sprintf("%d. message", index)] = msg
		}

		polr.Results = append(polr.Results, orv1alpha1.ReportResult{
			Policy:      check.Title,
			Rule:        check.ID,
			Description: check.Description,
			Properties:  props,
			Result:      result,
			Severity:    shared.MapORServerity(check.Severity),
			Category:    check.Category,
			Timestamp:   *report.CreationTimestamp.ProtoTime(),
			Source:      clusterrbac.TrivySource,
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

func CreateObjectReference(report *v1alpha1.ClusterRbacAssessmentReport) *corev1.ObjectReference {
	if len(report.OwnerReferences) == 1 {
		ref := report.OwnerReferences[0]

		return &corev1.ObjectReference{
			APIVersion: ref.APIVersion,
			Kind:       ref.Kind,
			Name:       ref.Name,
			UID:        ref.UID,
		}
	}
	return &corev1.ObjectReference{
		Kind: report.Labels[clusterrbac.KindLabel],
		Name: report.Annotations[clusterrbac.NameAnnotation],
	}
}

func (m *mapper) CreateReport(report *v1alpha1.ClusterRbacAssessmentReport) *orv1alpha1.ClusterReport {
	return &orv1alpha1.ClusterReport{
		ObjectMeta: v1.ObjectMeta{
			Name:            clusterrbac.GenerateReportName(report),
			Labels:          m.CreateLabels(report.Labels, clusterrbac.ReportLabels),
			OwnerReferences: report.OwnerReferences,
		},
		Source:  clusterrbac.TrivySource,
		Summary: CreateSummary(report),
		Results: []orv1alpha1.ReportResult{},
	}
}

func CreateSummary(report *v1alpha1.ClusterRbacAssessmentReport) orv1alpha1.ReportSummary {
	summary := orv1alpha1.ReportSummary{}

	for _, result := range report.Report.Checks {
		if result.Success {
			summary.Pass++
		} else {
			summary.Fail++
		}
	}

	return summary
}

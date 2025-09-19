package openreports

import (
	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/exposedsecret"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/policyreport/v1alpha2"
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.ExposedSecretReport, polr *orv1alpha1.Report) (*orv1alpha1.Report, bool) {
	if len(report.Report.Secrets) == 0 {
		return nil, false
	}

	var updated bool

	if polr == nil {
		polr = m.CreatePolicyReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, exposedsecret.ReportLabels)
		polr.Summary = CreateSummary(report)
		polr.Results = []orv1alpha1.ReportResult{}
		updated = true
	}

	duplCache := map[string]bool{}

	for _, check := range report.Report.Secrets {
		id := exposedsecret.GenerateID(string(polr.Scope.UID), polr.Scope.Name, check.Title, check.RuleID, check.Match, check.Category)

		if duplCache[id] {
			continue
		}

		polr.Results = append(polr.Results, orv1alpha1.ReportResult{
			Policy:      check.Title,
			Rule:        check.RuleID,
			Description: check.Match,
			Result:      v1alpha2.StatusWarn,
			Severity:    shared.MapORServerity(check.Severity),
			Category:    check.Category,
			Timestamp:   *report.CreationTimestamp.ProtoTime(),
			Source:      exposedsecret.TrivySource,
			Properties: map[string]string{
				"resultID": id,
			},
		})

		duplCache[id] = true
	}

	return polr, updated
}

func CreateObjectReference(report *v1alpha1.ExposedSecretReport) *corev1.ObjectReference {
	if len(report.OwnerReferences) == 1 {
		ref := report.OwnerReferences[0]

		return &corev1.ObjectReference{
			Namespace:  report.Namespace,
			APIVersion: ref.APIVersion,
			Kind:       ref.Kind,
			Name:       ref.Name,
			UID:        ref.UID,
		}
	}
	return &corev1.ObjectReference{
		Namespace: report.Labels[exposedsecret.NamespaceLabel],
		Kind:      report.Labels[exposedsecret.KindLabel],
		Name:      report.Annotations[exposedsecret.NameAnnotation],
	}
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.ExposedSecretReport) *orv1alpha1.Report {
	return &orv1alpha1.Report{
		ObjectMeta: v1.ObjectMeta{
			Name:            exposedsecret.GenerateReportName(report),
			Namespace:       report.Namespace,
			Labels:          m.CreateLabels(report.Labels, exposedsecret.ReportLabels),
			OwnerReferences: report.OwnerReferences,
		},
		Source:  exposedsecret.TrivySource,
		Summary: CreateSummary(report),
		Results: []orv1alpha1.ReportResult{},
		Scope:   CreateObjectReference(report),
	}
}

func CreateSummary(report *v1alpha1.ExposedSecretReport) orv1alpha1.ReportSummary {
	return orv1alpha1.ReportSummary{
		Warn: len(report.Report.Secrets),
	}
}

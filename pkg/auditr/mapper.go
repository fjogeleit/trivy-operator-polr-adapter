package auditr

import (
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/kyverno/kyverno/api/policyreport/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Severity = int

const (
	unknown Severity = iota
	low
	medium
	high
	critical
)

const (
	source       = "Trivy ConfigAudit"
	reportPrefix = "trivy-audit-polr"

	containerLabel = "trivy-operator.container.name"
	kindLabel      = "trivy-operator.resource.kind"
	nameLabel      = "trivy-operator.resource.name"
	namespaceLabel = "trivy-operator.resource.namespace"
)

var (
	reportLabels = map[string]string{
		"managed-by":            "trivy-operator-polr-adapter",
		"trivy-operator.source": "ConfigAuditReport",
	}
)

func Map(report *v1alpha1.ConfigAuditReport, polr *v1alpha2.PolicyReport) (*v1alpha2.PolicyReport, bool) {
	var updated bool

	if polr == nil {
		polr = CreatePolicyReport(report)
	} else {
		polr.Summary = v1alpha2.PolicyReportSummary{}
		polr.Results = []*v1alpha2.PolicyReportResult{}
		updated = true
	}

	res := CreateObjectReference(report)

	for _, check := range append(report.Report.Checks, report.Report.PodChecks...) {
		props := map[string]string{}

		for i, m := range check.Messages {
			props[fmt.Sprintf("%d. message", (i+1))] = m
		}

		if check.Success {
			polr.Summary.Pass++
		} else {
			polr.Summary.Fail++
		}

		polr.Results = append(polr.Results, &v1alpha2.PolicyReportResult{
			Policy:     check.Title,
			Rule:       check.ID,
			Message:    check.Description,
			Properties: props,
			Resources:  []*corev1.ObjectReference{res},
			Result:     MapResult(check.Success),
			Severity:   MapServerity(check.Severity),
			Category:   check.Category,
			Timestamp:  *report.Report.UpdateTimestamp.ProtoTime(),
			Source:     source,
		})
	}

	return polr, updated
}

func MapResult(success bool) v1alpha2.PolicyResult {
	if success {
		return v1alpha2.StatusPass
	}

	return v1alpha2.StatusFail
}

func MapServerity(severity v1alpha1.Severity) v1alpha2.PolicySeverity {
	if severity == v1alpha1.SeverityUnknown || severity == v1alpha1.SeverityNone {
		return ""
	} else if severity == v1alpha1.SeverityLow {
		return v1alpha2.SeverityLow
	} else if severity == v1alpha1.SeverityMedium {
		return v1alpha2.SeverityMedium
	}

	return v1alpha2.SeverityHigh
}

func CreateObjectReference(report *v1alpha1.ConfigAuditReport) *corev1.ObjectReference {
	if len(report.OwnerReferences) == 1 {
		ref := report.OwnerReferences[0].DeepCopy()

		return &corev1.ObjectReference{
			Namespace:  report.Namespace,
			APIVersion: ref.APIVersion,
			Kind:       ref.Kind,
			Name:       ref.Name,
			UID:        ref.UID,
		}
	}
	return &corev1.ObjectReference{
		Namespace: report.Labels[namespaceLabel],
		Kind:      report.Labels[kindLabel],
		Name:      report.Labels[nameLabel],
	}
}

func CreatePolicyReport(report *v1alpha1.ConfigAuditReport) *v1alpha2.PolicyReport {
	name := report.Name
	if len(report.OwnerReferences) == 1 {
		name = report.OwnerReferences[0].Name
	}

	return &v1alpha2.PolicyReport{
		ObjectMeta: v1.ObjectMeta{
			Name:            GeneratePolicyReportName(name),
			Namespace:       report.Namespace,
			Labels:          reportLabels,
			OwnerReferences: report.OwnerReferences,
		},
		Summary: v1alpha2.PolicyReportSummary{},
		Results: []*v1alpha2.PolicyReportResult{},
	}
}

func GeneratePolicyReportName(name string) string {
	return fmt.Sprintf("%s-%s", reportPrefix, name)
}

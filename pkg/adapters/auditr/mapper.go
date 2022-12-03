package auditr

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/kyverno/kyverno/api/policyreport/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	resultSource = "Trivy ConfigAudit"
	reportPrefix = "trivy-audit-polr"

	containerLabel = "trivy-operator.container.name"
	kindLabel      = "trivy-operator.resource.kind"
	nameLabel      = "trivy-operator.resource.name"
	namespaceLabel = "trivy-operator.resource.namespace"
)

var (
	reportLabels = map[string]string{
		"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
		"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
		"trivy-operator.source":        "ConfigAuditReport",
	}
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.ConfigAuditReport, polr *v1alpha2.PolicyReport) (*v1alpha2.PolicyReport, bool) {
	if len(report.Report.Checks) == 0 {
		return nil, false
	}

	var updated bool

	if polr == nil {
		polr = m.CreatePolicyReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, reportLabels)
		polr.Summary = v1alpha2.PolicyReportSummary{}
		polr.Results = []v1alpha2.PolicyReportResult{}
		updated = true
	}

	res := CreateObjectReference(report)

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

		polr.Results = append(polr.Results, v1alpha2.PolicyReportResult{
			Policy:     check.Title,
			Rule:       check.ID,
			Message:    message,
			Properties: props,
			Resources:  []corev1.ObjectReference{res},
			Result:     MapResult(check.Success),
			Severity:   shared.MapServerity(check.Severity),
			Category:   check.Category,
			Timestamp:  *report.CreationTimestamp.ProtoTime(),
			Source:     resultSource,
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

func CreateObjectReference(report *v1alpha1.ConfigAuditReport) corev1.ObjectReference {
	if len(report.OwnerReferences) == 1 {
		ref := report.OwnerReferences[0].DeepCopy()

		return corev1.ObjectReference{
			Namespace:  report.Namespace,
			APIVersion: ref.APIVersion,
			Kind:       ref.Kind,
			Name:       ref.Name,
			UID:        ref.UID,
		}
	}
	return corev1.ObjectReference{
		Namespace: report.Labels[namespaceLabel],
		Kind:      report.Labels[kindLabel],
		Name:      report.Labels[nameLabel],
	}
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.ConfigAuditReport) *v1alpha2.PolicyReport {
	return &v1alpha2.PolicyReport{
		ObjectMeta: v1.ObjectMeta{
			Name:            GeneratePolicyReportName(report),
			Namespace:       report.Namespace,
			Labels:          m.CreateLabels(report.Labels, reportLabels),
			OwnerReferences: report.OwnerReferences,
		},
		Summary: v1alpha2.PolicyReportSummary{},
		Results: []v1alpha2.PolicyReportResult{},
	}
}

func GeneratePolicyReportName(report *v1alpha1.ConfigAuditReport) string {
	name := report.Name
	if len(report.OwnerReferences) == 1 {
		name = fmt.Sprintf("%s-%s", strings.ToLower(report.OwnerReferences[0].Kind), report.OwnerReferences[0].Name)
	}

	return fmt.Sprintf("%s-%s", reportPrefix, name)
}

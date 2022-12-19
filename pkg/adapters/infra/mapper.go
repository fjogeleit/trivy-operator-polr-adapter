package infra

import (
	"crypto/sha1"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/kyverno/kyverno/api/policyreport/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	trivySource  = "Trivy InfraAssessment"
	reportPrefix = "trivy-infra-polr"
)

var (
	reportLabels = map[string]string{
		"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
		"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
		"trivy-operator.source":        "InfraAssessmentReport",
	}
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.InfraAssessmentReport, polr *v1alpha2.PolicyReport) (*v1alpha2.PolicyReport, bool) {
	var updated bool

	if polr == nil {
		polr = m.CreatePolicyReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, reportLabels)
		polr.Summary = v1alpha2.PolicyReportSummary{}
		polr.Results = []v1alpha2.PolicyReportResult{}
		updated = true
	}

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
			Source:     trivySource,
			Properties: props,
			Resources: []corev1.ObjectReference{
				shared.CreateObjectReference(report.Namespace, report.OwnerReferences, report.Labels),
			},
		})
	}

	return polr, updated
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.InfraAssessmentReport) *v1alpha2.PolicyReport {
	return &v1alpha2.PolicyReport{
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

func MapResult(success bool) v1alpha2.PolicyResult {
	if success {
		return v1alpha2.StatusPass
	}

	return v1alpha2.StatusFail
}

func generateID(target, policy, rule, category string, result v1alpha2.PolicyResult) string {
	id := fmt.Sprintf("%s_%s_%s_%s_%s", target, policy, rule, result, category)

	h := sha1.New()
	h.Write([]byte(id))

	return fmt.Sprintf("%x", h.Sum(nil))
}

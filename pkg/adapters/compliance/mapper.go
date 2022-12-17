package compliance

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
			status := MapResult(check.Success)

			props := map[string]string{
				"resultID": generateID(check.Target, result.Name, check.Title, check.Category, status),
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

			polr.Results = append(polr.Results, v1alpha2.PolicyReportResult{
				Policy:     fmt.Sprintf("%s %s", result.ID, result.Name),
				Category:   check.Category,
				Rule:       check.Title,
				Message:    message,
				Result:     status,
				Severity:   shared.MapServerity(check.Severity),
				Timestamp:  *report.CreationTimestamp.ProtoTime(),
				Source:     trivySource,
				Properties: props,
				Resources:  resources,
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

func generateID(target, policy, rule, category string, result v1alpha2.PolicyResult) string {
	id := fmt.Sprintf("%s_%s_%s_%s_%s", target, policy, rule, result, category)

	h := sha1.New()
	h.Write([]byte(id))

	return fmt.Sprintf("%x", h.Sum(nil))
}

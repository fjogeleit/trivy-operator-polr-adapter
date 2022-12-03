package rbac

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
	trivySource  = "Trivy RbacAssessment"
	reportPrefix = "trivy-rbac-polr"
	category     = "RbacAssessment"

	containerLabel = "trivy-operator.container.name"
	kindLabel      = "trivy-operator.resource.kind"
	nameAnnotation = "trivy-operator.resource.name"
	namespaceLabel = "trivy-operator.resource.namespace"
)

var (
	reportLabels = map[string]string{
		"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
		"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
		"trivy-operator.source":        "RbacAssessmentReport",
	}
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.RbacAssessmentReport, polr *v1alpha2.PolicyReport) (*v1alpha2.PolicyReport, bool) {
	if len(report.Report.Checks) == 0 {
		return nil, false
	}

	var updated bool

	if polr == nil {
		polr = m.CreatePolicyReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, reportLabels)
		polr.Summary = CreateSummary(report)
		polr.Results = []v1alpha2.PolicyReportResult{}
		updated = true
	}

	res := CreateObjectReference(report)
	duplCache := map[string]bool{}

	for _, check := range report.Report.Checks {
		result := MapResult(check.Success)
		id := generateID(string(res.UID), res.Name, check.Title, check.ID, string(result))
		if duplCache[id] {
			continue
		}

		props := map[string]string{
			"resultID": id,
		}

		var index int
		for _, msg := range check.Messages {
			if msg == "" {
				continue
			}
			index++
			props[fmt.Sprintf("%d. message", index)] = msg
		}

		polr.Results = append(polr.Results, v1alpha2.PolicyReportResult{
			Policy:     check.Title,
			Rule:       check.ID,
			Message:    check.Description,
			Properties: props,
			Resources:  []corev1.ObjectReference{res},
			Result:     result,
			Severity:   shared.MapServerity(check.Severity),
			Category:   check.Category,
			Timestamp:  *report.CreationTimestamp.ProtoTime(),
			Source:     trivySource,
		})

		duplCache[id] = true
	}

	return polr, updated
}

func MapResult(success bool) v1alpha2.PolicyResult {
	if success {
		return v1alpha2.StatusPass
	}

	return v1alpha2.StatusFail
}

func CreateObjectReference(report *v1alpha1.RbacAssessmentReport) corev1.ObjectReference {
	if len(report.OwnerReferences) == 1 {
		ref := report.OwnerReferences[0]

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
		Name:      report.Annotations[nameAnnotation],
	}
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.RbacAssessmentReport) *v1alpha2.PolicyReport {
	return &v1alpha2.PolicyReport{
		ObjectMeta: v1.ObjectMeta{
			Name:            GeneratePolicyReportName(report),
			Namespace:       report.Namespace,
			Labels:          m.CreateLabels(report.Labels, reportLabels),
			OwnerReferences: report.OwnerReferences,
		},
		Summary: CreateSummary(report),
		Results: []v1alpha2.PolicyReportResult{},
	}
}

func CreateSummary(report *v1alpha1.RbacAssessmentReport) v1alpha2.PolicyReportSummary {
	summary := v1alpha2.PolicyReportSummary{}

	for _, result := range report.Report.Checks {
		if result.Success {
			summary.Pass++
		} else {
			summary.Fail++
		}
	}

	return summary
}

func GeneratePolicyReportName(report *v1alpha1.RbacAssessmentReport) string {
	return fmt.Sprintf("%s-%s", reportPrefix, report.Name)
}

func generateID(uid, name, policy, rule, result string) string {
	id := fmt.Sprintf("%s_%s_%s_%s_%s", uid, name, policy, rule, result)

	h := sha1.New()
	h.Write([]byte(id))

	return fmt.Sprintf("%x", h.Sum(nil))
}

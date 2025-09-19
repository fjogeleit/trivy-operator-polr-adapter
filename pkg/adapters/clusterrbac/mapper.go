package clusterrbac

import (
	"crypto/sha1"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/policyreport/v1alpha2"
)

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.ClusterRbacAssessmentReport, polr *v1alpha2.ClusterPolicyReport) (*v1alpha2.ClusterPolicyReport, bool) {
	if len(report.Report.Checks) == 0 {
		return nil, false
	}

	var updated bool

	if polr == nil {
		polr = m.CreatePolicyReport(report)
	} else {
		polr.Labels = m.CreateLabels(report.Labels, ReportLabels)
		polr.Summary = CreateSummary(report)
		polr.Results = []v1alpha2.PolicyReportResult{}
		updated = true
	}

	polr.Scope = CreateObjectReference(report)

	for _, check := range report.Report.Checks {

		result := MapResult(check.Success)

		props := map[string]string{
			"resultID": GenerateID(string(polr.Scope.UID), polr.Scope.Name, check.Title, check.ID, string(result)),
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
			Result:     result,
			Severity:   shared.MapServerity(check.Severity),
			Category:   check.Category,
			Timestamp:  *report.CreationTimestamp.ProtoTime(),
			Source:     TrivySource,
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
		Kind: report.Labels[KindLabel],
		Name: report.Annotations[NameAnnotation],
	}
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.ClusterRbacAssessmentReport) *v1alpha2.ClusterPolicyReport {
	return &v1alpha2.ClusterPolicyReport{
		ObjectMeta: v1.ObjectMeta{
			Name:            GenerateReportName(report),
			Labels:          m.CreateLabels(report.Labels, ReportLabels),
			OwnerReferences: report.OwnerReferences,
		},
		Summary: CreateSummary(report),
		Results: []v1alpha2.PolicyReportResult{},
	}
}

func CreateSummary(report *v1alpha1.ClusterRbacAssessmentReport) v1alpha2.PolicyReportSummary {
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

func GenerateReportName(report *v1alpha1.ClusterRbacAssessmentReport) string {
	return fmt.Sprintf("%s-%s", ReportPrefix, report.Name)
}

func GenerateID(uid, name, policy, rule, result string) string {
	id := fmt.Sprintf("%s_%s_%s_%s_%s", uid, name, policy, rule, result)

	h := sha1.New()
	h.Write([]byte(id))

	return fmt.Sprintf("%x", h.Sum(nil))
}

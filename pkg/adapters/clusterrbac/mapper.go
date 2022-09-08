package clusterrbac

import (
	"crypto/sha1"
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
	trivySource  = "Trivy RbacAssessment"
	reportPrefix = "trivy-rbac-cpolr"
	category     = "ClusterRbacAssessment"

	containerLabel = "trivy-operator.container.name"
	kindLabel      = "trivy-operator.resource.kind"
	nameAnnotation = "trivy-operator.resource.name"
)

var (
	reportLabels = map[string]string{
		"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
		"trivy-operator.source":        "ClusterRbacAssessmentReport",
	}
)

func Map(report *v1alpha1.ClusterRbacAssessmentReport, polr *v1alpha2.ClusterPolicyReport) (*v1alpha2.ClusterPolicyReport, bool) {
	if len(report.Report.Checks) == 0 {
		return nil, false
	}

	var updated bool

	if polr == nil {
		polr = CreatePolicyReport(report)
	} else {
		polr.Summary = CreateSummary(report)
		polr.Results = []v1alpha2.PolicyReportResult{}
		updated = true
	}

	res := CreateObjectReference(report)

	for _, check := range report.Report.Checks {

		result := MapResult(check.Success)

		props := map[string]string{
			"resultID": generateID(string(res.UID), res.Name, check.Title, check.ID, string(result)),
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
			Severity:   MapServerity(check.Severity),
			Category:   check.Category,
			Timestamp:  *report.CreationTimestamp.ProtoTime(),
			Source:     trivySource,
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
	if severity == v1alpha1.SeverityUnknown {
		return ""
	} else if severity == v1alpha1.SeverityLow {
		return v1alpha2.SeverityLow
	} else if severity == v1alpha1.SeverityMedium {
		return v1alpha2.SeverityMedium
	}

	return v1alpha2.SeverityHigh
}

func CreateObjectReference(report *v1alpha1.ClusterRbacAssessmentReport) corev1.ObjectReference {
	if len(report.OwnerReferences) == 1 {
		ref := report.OwnerReferences[0]

		return corev1.ObjectReference{
			APIVersion: ref.APIVersion,
			Kind:       ref.Kind,
			Name:       ref.Name,
			UID:        ref.UID,
		}
	}
	return corev1.ObjectReference{
		Kind: report.Labels[kindLabel],
		Name: report.Annotations[nameAnnotation],
	}
}

func CreatePolicyReport(report *v1alpha1.ClusterRbacAssessmentReport) *v1alpha2.ClusterPolicyReport {
	return &v1alpha2.ClusterPolicyReport{
		ObjectMeta: v1.ObjectMeta{
			Name:            GeneratePolicyReportName(report),
			Labels:          reportLabels,
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

func GeneratePolicyReportName(report *v1alpha1.ClusterRbacAssessmentReport) string {
	return fmt.Sprintf("%s-%s", reportPrefix, report.Name)
}

func generateID(uid, name, policy, rule, result string) string {
	id := fmt.Sprintf("%s_%s_%s_%s_%s", uid, name, policy, rule, result)

	h := sha1.New()
	h.Write([]byte(id))

	return fmt.Sprintf("%x", h.Sum(nil))
}
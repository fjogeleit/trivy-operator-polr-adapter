package exposedsecret

import (
	"crypto/sha1"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/policyreport/v1alpha2"
)

const (
	trivySource  = "Trivy ExposedSecrets"
	reportPrefix = "trivy-exp-secret-polr"
	category     = "ExposedSecret"

	containerLabel = "trivy-operator.container.name"
	kindLabel      = "trivy-operator.resource.kind"
	nameAnnotation = "trivy-operator.resource.name"
	namespaceLabel = "trivy-operator.resource.namespace"
)

var reportLabels = map[string]string{
	"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
	"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
	"trivy-operator.source":        "ExposedSecretReport",
}

type mapper struct {
	shared.LabelMapper
}

func (m *mapper) Map(report *v1alpha1.ExposedSecretReport, polr *v1alpha2.PolicyReport) (*v1alpha2.PolicyReport, bool) {
	if len(report.Report.Secrets) == 0 {
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

	duplCache := map[string]bool{}

	for _, check := range report.Report.Secrets {
		id := generateID(string(polr.Scope.UID), polr.Scope.Name, check.Title, check.RuleID, check.Match, check.Category)

		if duplCache[id] {
			continue
		}

		polr.Results = append(polr.Results, v1alpha2.PolicyReportResult{
			Policy:    check.Title,
			Rule:      check.RuleID,
			Message:   check.Match,
			Result:    v1alpha2.StatusWarn,
			Severity:  shared.MapServerity(check.Severity),
			Category:  check.Category,
			Timestamp: *report.CreationTimestamp.ProtoTime(),
			Source:    trivySource,
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
		Namespace: report.Labels[namespaceLabel],
		Kind:      report.Labels[kindLabel],
		Name:      report.Annotations[nameAnnotation],
	}
}

func (m *mapper) CreatePolicyReport(report *v1alpha1.ExposedSecretReport) *v1alpha2.PolicyReport {
	return &v1alpha2.PolicyReport{
		ObjectMeta: v1.ObjectMeta{
			Name:            GeneratePolicyReportName(report),
			Namespace:       report.Namespace,
			Labels:          m.CreateLabels(report.Labels, reportLabels),
			OwnerReferences: report.OwnerReferences,
		},
		Summary: CreateSummary(report),
		Results: []v1alpha2.PolicyReportResult{},
		Scope:   CreateObjectReference(report),
	}
}

func CreateSummary(report *v1alpha1.ExposedSecretReport) v1alpha2.PolicyReportSummary {
	return v1alpha2.PolicyReportSummary{
		Warn: len(report.Report.Secrets),
	}
}

func GeneratePolicyReportName(report *v1alpha1.ExposedSecretReport) string {
	name := report.Name
	if len(report.OwnerReferences) == 1 {
		name = fmt.Sprintf("%s-%s", strings.ToLower(report.OwnerReferences[0].Kind), report.OwnerReferences[0].Name)
	}

	return fmt.Sprintf("%s-%s", reportPrefix, name)
}

func generateID(uid, name, policy, rule, result, category string) string {
	id := fmt.Sprintf("%s_%s_%s_%s_%s_%s", uid, name, policy, rule, result, category)

	h := sha1.New()
	h.Write([]byte(id))

	return fmt.Sprintf("%x", h.Sum(nil))
}

package infra

const (
	TrivySource  = "Trivy InfraAssessment"
	ReportPrefix = "trivy-infra-polr"
)

var ReportLabels = map[string]string{
	"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
	"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
	"trivy-operator.source":        "InfraAssessmentReport",
}

package clusterinfra

const (
	TrivySource  = "Trivy InfraAssessment"
	ReportPrefix = "trivy-infra-cpolr"
)

var ReportLabels = map[string]string{
	"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
	"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
	"trivy-operator.source":        "ClusterInfraAssessmentReport",
}

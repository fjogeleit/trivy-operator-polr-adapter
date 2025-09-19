package clusterrbac

const (
	TrivySource  = "Trivy RbacAssessment"
	ReportPrefix = "trivy-rbac-cpolr"
	Category     = "ClusterRbacAssessment"

	ContainerLabel = "trivy-operator.container.name"
	KindLabel      = "trivy-operator.resource.kind"
	NameAnnotation = "trivy-operator.resource.name"
)

var ReportLabels = map[string]string{
	"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
	"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
	"trivy-operator.source":        "ClusterRbacAssessmentReport",
}

package exposedsecret

const (
	TrivySource  = "Trivy ExposedSecrets"
	ReportPrefix = "trivy-exp-secret-polr"
	Category     = "ExposedSecret"

	ContainerLabel = "trivy-operator.container.name"
	KindLabel      = "trivy-operator.resource.kind"
	NameAnnotation = "trivy-operator.resource.name"
	NamespaceLabel = "trivy-operator.resource.namespace"
)

var ReportLabels = map[string]string{
	"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
	"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
	"trivy-operator.source":        "ExposedSecretReport",
}

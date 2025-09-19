package vulnr

const (
	TrivySource  = "Trivy Vulnerability"
	ReportPrefix = "trivy-vuln-polr"
	Category     = "Vulnerability Scan"

	ContainerLabel = "trivy-operator.container.name"
	KindLabel      = "trivy-operator.resource.kind"
	NameLabel      = "trivy-operator.resource.name"
	NamespaceLabel = "trivy-operator.resource.namespace"
)

var ReportLabels = map[string]string{
	"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
	"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
	"trivy-operator.source":        "VulnerabilityReport",
}

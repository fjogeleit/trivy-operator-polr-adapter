package auditr

const (
	TrivySource  = "Trivy ConfigAudit"
	ReportPrefix = "trivy-audit-polr"
)

var ReportLabels = map[string]string{
	"app.kubernetes.io/managed-by": "trivy-operator-polr-adapter",
	"app.kubernetes.io/created-by": "trivy-operator-polr-adapter",
	"trivy-operator.source":        "ConfigAuditReport",
}

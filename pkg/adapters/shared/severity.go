package shared

import (
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/kyverno/kyverno/api/policyreport/v1alpha2"
)

func MapServerity(severity v1alpha1.Severity) v1alpha2.PolicySeverity {
	if severity == v1alpha1.SeverityUnknown {
		return ""
	} else if severity == v1alpha1.SeverityLow {
		return v1alpha2.SeverityLow
	} else if severity == v1alpha1.SeverityMedium {
		return v1alpha2.SeverityMedium
	} else if severity == v1alpha1.SeverityHigh {
		return v1alpha2.SeverityHigh
	} else if severity == v1alpha1.SeverityCritical {
		return v1alpha2.SeverityCritical
	}

	return v1alpha2.SeverityInfo
}

func MapResult(severity v1alpha1.Severity) v1alpha2.PolicyResult {
	if severity == v1alpha1.SeverityUnknown {
		return v1alpha2.StatusSkip
	} else if severity == v1alpha1.SeverityLow {
		return v1alpha2.StatusWarn
	} else if severity == v1alpha1.SeverityMedium {
		return v1alpha2.StatusWarn
	}

	return v1alpha2.StatusFail
}

package shared

import (
	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/policyreport/v1alpha2"
)

func MapServerity(severity v1alpha1.Severity) v1alpha2.PolicySeverity {
	switch severity {
	case v1alpha1.SeverityCritical:
		return v1alpha2.SeverityCritical
	case v1alpha1.SeverityHigh:
		return v1alpha2.SeverityHigh
	case v1alpha1.SeverityMedium:
		return v1alpha2.SeverityMedium
	case v1alpha1.SeverityLow:
		return v1alpha2.SeverityLow
	case v1alpha1.SeverityUnknown:
		return ""
	}

	return v1alpha2.SeverityInfo
}

func MapResult(severity v1alpha1.Severity) v1alpha2.PolicyResult {
	switch severity {
	case v1alpha1.SeverityCritical:
		return v1alpha2.StatusFail
	case v1alpha1.SeverityHigh:
		return v1alpha2.StatusFail
	case v1alpha1.SeverityMedium:
		return v1alpha2.StatusWarn
	case v1alpha1.SeverityUnknown:
		return v1alpha2.StatusSkip
	case v1alpha1.SeverityLow:
		return v1alpha2.StatusWarn
	default:
		return v1alpha2.StatusFail
	}
}

func MapORServerity(severity v1alpha1.Severity) orv1alpha1.ResultSeverity {
	switch severity {
	case v1alpha1.SeverityCritical:
		return v1alpha2.SeverityCritical
	case v1alpha1.SeverityHigh:
		return v1alpha2.SeverityHigh
	case v1alpha1.SeverityMedium:
		return v1alpha2.SeverityMedium
	case v1alpha1.SeverityLow:
		return v1alpha2.SeverityLow
	case v1alpha1.SeverityUnknown:
		return ""
	}

	return v1alpha2.SeverityInfo
}

func MapORResult(severity v1alpha1.Severity) orv1alpha1.Result {
	switch severity {
	case v1alpha1.SeverityCritical:
		return v1alpha2.StatusFail
	case v1alpha1.SeverityHigh:
		return v1alpha2.StatusFail
	case v1alpha1.SeverityMedium:
		return v1alpha2.StatusWarn
	case v1alpha1.SeverityUnknown:
		return v1alpha2.StatusSkip
	case v1alpha1.SeverityLow:
		return v1alpha2.StatusWarn
	default:
		return v1alpha2.StatusFail
	}
}

package vulnr

import (
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	pr "github.com/kyverno/kyverno/pkg/client/clientset/versioned/typed/policyreport/v1alpha2"
	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

type PolicyReportClient struct {
	k8sClient pr.Wgpolicyk8sV1alpha2Interface
}

func (p *PolicyReportClient) GenerateReport(ctx context.Context, report *v1alpha1.VulnerabilityReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		polr, err := p.k8sClient.PolicyReports(report.Namespace).Get(ctx, GeneratePolicyReportName(report), v1.GetOptions{})
		if !errors.IsNotFound(err) && err != nil {
			return err
		} else if errors.IsNotFound(err) {
			polr = nil
		}

		polr, updated := Map(report, polr)
		if updated {
			_, err = p.k8sClient.PolicyReports(report.Namespace).Update(ctx, polr, v1.UpdateOptions{})
		} else {
			_, err = p.k8sClient.PolicyReports(report.Namespace).Create(ctx, polr, v1.CreateOptions{})
		}

		if err != nil {
			return fmt.Errorf("failed to create PolicyReport in namespace %s: %s", report.Namespace, err)
		}

		return nil
	})
}

func (p *PolicyReportClient) DeleteReport(ctx context.Context, report *v1alpha1.VulnerabilityReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return p.k8sClient.PolicyReports(report.Namespace).Delete(ctx, GeneratePolicyReportName(report), v1.DeleteOptions{})
	})
}

func NewPolicyReportClient(client pr.Wgpolicyk8sV1alpha2Interface) *PolicyReportClient {
	return &PolicyReportClient{
		k8sClient: client,
	}
}

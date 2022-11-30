package kubebench

import (
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	pr "github.com/kyverno/kyverno/pkg/client/clientset/versioned/typed/policyreport/v1alpha2"
	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

type PolicyReportClient struct {
	k8sClient pr.Wgpolicyk8sV1alpha2Interface
	mapper    *mapper
}

func (p *PolicyReportClient) GenerateReport(ctx context.Context, report *v1alpha1.CISKubeBenchReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		polr, err := p.k8sClient.ClusterPolicyReports().Get(ctx, GeneratePolicyReportName(report.Name), v1.GetOptions{})
		if !errors.IsNotFound(err) && err != nil {
			return err
		} else if errors.IsNotFound(err) {
			polr = nil
		}

		polr, updated := p.mapper.Map(report, polr)
		if polr == nil {
			return nil
		} else if updated {
			_, err = p.k8sClient.ClusterPolicyReports().Update(ctx, polr, v1.UpdateOptions{})
		} else {
			_, err = p.k8sClient.ClusterPolicyReports().Create(ctx, polr, v1.CreateOptions{})
		}

		if err != nil {
			return fmt.Errorf("failed to create ClusterPolicyReport %s: %s", report.Name, err)
		}

		return nil
	})
}

func (p *PolicyReportClient) DeleteReport(ctx context.Context, report *v1alpha1.CISKubeBenchReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		err := p.k8sClient.ClusterPolicyReports().Delete(ctx, GeneratePolicyReportName(report.Name), v1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return err
		}

		return err
	})
}

func NewPolicyReportClient(client pr.Wgpolicyk8sV1alpha2Interface, applyLabels []string) *PolicyReportClient {
	return &PolicyReportClient{
		k8sClient: client,
		mapper:    &mapper{shared.NewLabelMapper(applyLabels)},
	}
}

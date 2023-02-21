package infra

import (
	"fmt"

	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	pr "github.com/fjogeleit/trivy-operator-polr-adapter/pkg/client/clientset/versioned/typed/policyreport/v1alpha2"
)

type PolicyReportClient struct {
	k8sClient pr.Wgpolicyk8sV1alpha2Interface
	mapper    *mapper
}

func (p *PolicyReportClient) GenerateReport(ctx context.Context, report *v1alpha1.InfraAssessmentReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		polr, err := p.k8sClient.PolicyReports(report.Namespace).Get(ctx, GeneratePolicyReportName(report.Name), v1.GetOptions{})
		if !errors.IsNotFound(err) && err != nil {
			return err
		} else if errors.IsNotFound(err) {
			polr = nil
		}

		polr, updated := p.mapper.Map(report, polr)
		if updated {
			_, err = p.k8sClient.PolicyReports(report.Namespace).Update(ctx, polr, v1.UpdateOptions{})
		} else {
			_, err = p.k8sClient.PolicyReports(report.Namespace).Create(ctx, polr, v1.CreateOptions{})
		}

		if err != nil {
			return fmt.Errorf("failed to create PolicyReport: %s", err)
		}

		return nil
	})
}

func (p *PolicyReportClient) DeleteReport(ctx context.Context, report *v1alpha1.InfraAssessmentReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		err := p.k8sClient.PolicyReports(report.Namespace).Delete(ctx, GeneratePolicyReportName(report.Name), v1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return err
		}

		return nil
	})
}

func NewPolicyReportClient(client pr.Wgpolicyk8sV1alpha2Interface, applyLabels []string) *PolicyReportClient {
	return &PolicyReportClient{
		k8sClient: client,
		mapper:    &mapper{shared.NewLabelMapper(applyLabels)},
	}
}

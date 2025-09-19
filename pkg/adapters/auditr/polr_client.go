package auditr

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

type ReportClient interface {
	GenerateReport(ctx context.Context, report *v1alpha1.ConfigAuditReport) error
	DeleteReport(ctx context.Context, report *v1alpha1.ConfigAuditReport) error
}

type reportClient struct {
	k8sClient pr.Wgpolicyk8sV1alpha2Interface
	mapper    *mapper
}

func (p *reportClient) GenerateReport(ctx context.Context, report *v1alpha1.ConfigAuditReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		polr, err := p.k8sClient.PolicyReports(report.Namespace).Get(ctx, GenerateReportName(report), v1.GetOptions{})
		if !errors.IsNotFound(err) && err != nil {
			return err
		} else if errors.IsNotFound(err) {
			polr = nil
		}

		polr, updated := p.mapper.Map(report, polr)
		if polr == nil {
			return nil
		} else if updated {
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

func (p *reportClient) DeleteReport(ctx context.Context, report *v1alpha1.ConfigAuditReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		err := p.k8sClient.PolicyReports(report.Namespace).Delete(ctx, GenerateReportName(report), v1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return err
		}

		return nil
	})
}

func NewReportClient(client pr.Wgpolicyk8sV1alpha2Interface, applyLabels []string) ReportClient {
	return &reportClient{
		k8sClient: client,
		mapper:    &mapper{shared.NewLabelMapper(applyLabels)},
	}
}

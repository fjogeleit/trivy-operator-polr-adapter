package rbac

import (
	"fmt"

	or "github.com/openreports/reports-api/pkg/client/clientset/versioned/typed/openreports.io/v1alpha1"
	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/rbac"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
)

type reportClient struct {
	k8sClient or.OpenreportsV1alpha1Interface
	mapper    *mapper
}

func (p *reportClient) GenerateReport(ctx context.Context, report *v1alpha1.RbacAssessmentReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		polr, err := p.k8sClient.Reports(report.Namespace).Get(ctx, rbac.GenerateReportName(report), v1.GetOptions{})
		if !errors.IsNotFound(err) && err != nil {
			return err
		} else if errors.IsNotFound(err) {
			polr = nil
		}

		polr, updated := p.mapper.Map(report, polr)
		if polr == nil {
			return nil
		} else if updated {
			_, err = p.k8sClient.Reports(report.Namespace).Update(ctx, polr, v1.UpdateOptions{})
		} else {
			_, err = p.k8sClient.Reports(report.Namespace).Create(ctx, polr, v1.CreateOptions{})
		}

		if err != nil {
			return fmt.Errorf("failed to create PolicyReport in namespace %s: %s", report.Namespace, err)
		}

		return nil
	})
}

func (p *reportClient) DeleteReport(ctx context.Context, report *v1alpha1.RbacAssessmentReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		err := p.k8sClient.Reports(report.Namespace).Delete(ctx, rbac.GenerateReportName(report), v1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return err
		}

		return nil
	})
}

func NewReportClient(client or.OpenreportsV1alpha1Interface, applyLabels []string) rbac.ReportClient {
	return &reportClient{
		k8sClient: client,
		mapper: &mapper{
			shared.NewLabelMapper(applyLabels),
		},
	}
}

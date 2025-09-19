package openreports

import (
	"fmt"

	or "github.com/openreports/reports-api/pkg/client/clientset/versioned/typed/openreports.io/v1alpha1"
	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/clusterrbac"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
)

type PolicyReportClient struct {
	k8sClient or.OpenreportsV1alpha1Interface
	mapper    *mapper
}

func (p *PolicyReportClient) GenerateReport(ctx context.Context, report *v1alpha1.ClusterRbacAssessmentReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		polr, err := p.k8sClient.ClusterReports().Get(ctx, clusterrbac.GenerateReportName(report), v1.GetOptions{})
		if !errors.IsNotFound(err) && err != nil {
			return err
		} else if errors.IsNotFound(err) {
			polr = nil
		}

		polr, updated := p.mapper.Map(report, polr)
		if polr == nil {
			return nil
		} else if updated {
			_, err = p.k8sClient.ClusterReports().Update(ctx, polr, v1.UpdateOptions{})
		} else {
			_, err = p.k8sClient.ClusterReports().Create(ctx, polr, v1.CreateOptions{})
		}

		if err != nil {
			return fmt.Errorf("failed to create ClusterReport %s: %s", report.Name, err)
		}

		return nil
	})
}

func (p *PolicyReportClient) DeleteReport(ctx context.Context, report *v1alpha1.ClusterRbacAssessmentReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		err := p.k8sClient.ClusterReports().Delete(ctx, clusterrbac.GenerateReportName(report), v1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return err
		}

		return nil
	})
}

func NewReportClient(client or.OpenreportsV1alpha1Interface, applyLabels []string) *PolicyReportClient {
	return &PolicyReportClient{
		k8sClient: client,
		mapper:    &mapper{shared.NewLabelMapper(applyLabels)},
	}
}

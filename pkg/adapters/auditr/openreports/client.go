package openreports

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	or "github.com/openreports/reports-api/pkg/client/clientset/versioned/typed/openreports.io/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/auditr"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/shared"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
)

type reportClient struct {
	k8sClient or.OpenreportsV1alpha1Interface
	mapper    *mapper
	logger    logr.Logger
}

func (p *reportClient) GenerateReport(ctx context.Context, report *v1alpha1.ConfigAuditReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		polr, err := p.k8sClient.Reports(report.Namespace).Get(ctx, auditr.GenerateReportName(report), v1.GetOptions{})
		if !errors.IsNotFound(err) && err != nil {
			return err
		} else if errors.IsNotFound(err) {
			polr = nil
		}

		polr, updated := p.mapper.Map(report, polr)
		if polr == nil {
			return nil
		} else if len(polr.Results) == 0 {
			p.logger.Info("No results, deleting Report", "report", report.Name, "namespace", report.Namespace)
			err = p.DeleteReport(ctx, report)
		} else if updated {
			p.logger.Info("Updating Report", "report", report.Name, "namespace", report.Namespace)
			_, err = p.k8sClient.Reports(report.Namespace).Update(ctx, polr, v1.UpdateOptions{})
		} else {
			p.logger.Info("Creating Report", "report", report.Name, "namespace", report.Namespace)
			_, err = p.k8sClient.Reports(report.Namespace).Create(ctx, polr, v1.CreateOptions{})
		}

		if err != nil {
			return fmt.Errorf("failed to create PolicyReport in namespace %s: %w", report.Namespace, err)
		}

		return nil
	})
}

func (p *reportClient) DeleteReport(ctx context.Context, report *v1alpha1.ConfigAuditReport) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		err := p.k8sClient.Reports(report.Namespace).Delete(ctx, auditr.GenerateReportName(report), v1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return err
		}

		return nil
	})
}

func (p *reportClient) Cleanup(ctx context.Context) error {
	return shared.OpenReportCleanup(ctx, p.k8sClient, "ConfigAuditReport")
}

func NewReportClient(client or.OpenreportsV1alpha1Interface, applyLabels []string) auditr.ReportClient {
	return &reportClient{
		k8sClient: client,
		mapper:    &mapper{shared.NewLabelMapper(applyLabels)},
		logger:    ctrl.Log.WithName("ConfigAuditReportOpenReportsClient").V(4),
	}
}

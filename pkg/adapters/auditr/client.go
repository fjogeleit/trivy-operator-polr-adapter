package auditr

import (
	"context"
	"log"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/kyverno/kyverno/pkg/client/clientset/versioned/typed/policyreport/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type Client struct {
	client     controller.Controller
	polrClient *PolicyReportClient
}

func (e *Client) StartWatching(ctx context.Context) error {
	return e.client.Watch(&source.Kind{Type: &v1alpha1.ConfigAuditReport{}}, &handler.EnqueueRequestForObject{}, predicate.Funcs{
		CreateFunc: func(event event.CreateEvent) bool {
			if report, ok := event.Object.(*v1alpha1.ConfigAuditReport); ok {
				err := e.polrClient.GenerateReport(ctx, report)
				if err != nil {
					log.Printf("[ERROR] ConfigAuditReport: Failed to process report %s; %s", report.Name, err)
				}

			}

			return true
		},
		UpdateFunc: func(event event.UpdateEvent) bool {
			if report, ok := event.ObjectNew.(*v1alpha1.ConfigAuditReport); ok {
				err := e.polrClient.GenerateReport(ctx, report)
				if err != nil {
					log.Printf("[ERROR] ConfigAuditReport: Failed to process report %s; %s", report.Name, err)
				}
			}

			return true
		},
		DeleteFunc: func(event event.DeleteEvent) bool {
			if report, ok := event.Object.(*v1alpha1.ConfigAuditReport); ok {
				err := e.polrClient.DeleteReport(ctx, report)
				if err != nil {
					log.Printf("[ERROR] ConfigAuditReport: Failed to delete report %s; %s", report.Name, err)
				}
			}

			return true
		},
	})
}

func NewClient(client controller.Controller, polrClient v1alpha2.Wgpolicyk8sV1alpha2Interface, applyLabels []string) *Client {
	return &Client{
		client:     client,
		polrClient: NewPolicyReportClient(polrClient, applyLabels),
	}
}

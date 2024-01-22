package clustervulnr

import (
	"context"
	"log"

	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/client/clientset/versioned/typed/policyreport/v1alpha2"
)

type Client struct {
	manager    manager.Manager
	client     controller.Controller
	polrClient *PolicyReportClient
}

func (e *Client) StartWatching(ctx context.Context) error {
	return e.client.Watch(source.Kind(e.manager.GetCache(), &v1alpha1.ClusterVulnerabilityReport{}), &handler.EnqueueRequestForObject{}, predicate.Funcs{
		CreateFunc: func(event event.CreateEvent) bool {
			if report, ok := event.Object.(*v1alpha1.ClusterVulnerabilityReport); ok {
				err := e.polrClient.GenerateReport(ctx, report)
				if err != nil {
					log.Printf("[ERROR] ClusterVulnerabilityReport: Failed to process report %s; %s", report.Name, err)
				}
			}

			return true
		},
		UpdateFunc: func(event event.UpdateEvent) bool {
			if report, ok := event.ObjectNew.(*v1alpha1.ClusterVulnerabilityReport); ok {
				err := e.polrClient.GenerateReport(ctx, report)
				if err != nil {
					log.Printf("[ERROR] ClusterVulnerabilityReport: Failed to process report %s; %s", report.Name, err)
				}
			}

			return true
		},
		DeleteFunc: func(event event.DeleteEvent) bool {
			if report, ok := event.Object.(*v1alpha1.ClusterVulnerabilityReport); ok {
				err := e.polrClient.DeleteReport(ctx, report)
				if err != nil {
					log.Printf("[ERROR] ClusterVulnerabilityReport: Failed to delete report %s; %s", report.Name, err)
				}
			}

			return true
		},
	})
}

func NewClient(mgr manager.Manager, client controller.Controller, polrClient v1alpha2.Wgpolicyk8sV1alpha2Interface, applyLabels []string) *Client {
	return &Client{
		manager:    mgr,
		client:     client,
		polrClient: NewPolicyReportClient(polrClient, applyLabels),
	}
}

package vulnr

import (
	"context"
	"log"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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
	return e.client.Watch(source.Kind(e.manager.GetCache(), &v1alpha1.VulnerabilityReport{}, &handler.TypedFuncs[*v1alpha1.VulnerabilityReport, reconcile.Request]{
		CreateFunc: func(ctx context.Context, event event.TypedCreateEvent[*v1alpha1.VulnerabilityReport], _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			err := e.polrClient.GenerateReport(ctx, event.Object)
			if err != nil {
				log.Printf("[ERROR] VulnerabilityReport: Failed to process report %s; %s", event.Object.Name, err)
			}
		},
		UpdateFunc: func(ctx context.Context, event event.TypedUpdateEvent[*v1alpha1.VulnerabilityReport], _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			err := e.polrClient.GenerateReport(ctx, event.ObjectNew)
			if err != nil {
				log.Printf("[ERROR] VulnerabilityReport: Failed to process report %s; %s", event.ObjectNew.Name, err)
			}
		},
		DeleteFunc: func(ctx context.Context, event event.TypedDeleteEvent[*v1alpha1.VulnerabilityReport], _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			err := e.polrClient.DeleteReport(ctx, event.Object)
			if err != nil {
				log.Printf("[ERROR] VulnerabilityReport: Failed to delete report %s; %s", event.Object.Name, err)
			}
		},
	}))
}

func NewClient(mgr manager.Manager, client controller.Controller, polrClient v1alpha2.Wgpolicyk8sV1alpha2Interface, applyLabels []string) *Client {
	return &Client{
		manager:    mgr,
		client:     client,
		polrClient: NewPolicyReportClient(polrClient, applyLabels),
	}
}

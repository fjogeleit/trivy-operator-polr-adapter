package clustervulnr

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
)

type Client interface {
	StartWatching(ctx context.Context) error
}

type client struct {
	manager    manager.Manager
	controller controller.Controller
	client     ReportClient
}

func (e *client) StartWatching(ctx context.Context) error {
	return e.controller.Watch(source.Kind(e.manager.GetCache(), &v1alpha1.ClusterVulnerabilityReport{}, &handler.TypedFuncs[*v1alpha1.ClusterVulnerabilityReport, reconcile.Request]{
		CreateFunc: func(ctx context.Context, event event.TypedCreateEvent[*v1alpha1.ClusterVulnerabilityReport], _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			err := e.client.GenerateReport(ctx, event.Object)
			if err != nil {
				log.Printf("[ERROR] ClusterVulnerabilityReport: Failed to process report %s; %s", event.Object.Name, err)
			}
		},
		UpdateFunc: func(ctx context.Context, event event.TypedUpdateEvent[*v1alpha1.ClusterVulnerabilityReport], _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			err := e.client.GenerateReport(ctx, event.ObjectNew)
			if err != nil {
				log.Printf("[ERROR] ClusterVulnerabilityReport: Failed to process report %s; %s", event.ObjectNew.Name, err)
			}
		},
		DeleteFunc: func(ctx context.Context, event event.TypedDeleteEvent[*v1alpha1.ClusterVulnerabilityReport], _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			err := e.client.DeleteReport(ctx, event.Object)
			if err != nil {
				log.Printf("[ERROR] ClusterVulnerabilityReport: Failed to delete report %s; %s", event.Object.Name, err)
			}
		},
	}))
}

func NewClient(mgr manager.Manager, controller controller.Controller, orClient ReportClient) Client {
	return &client{
		manager:    mgr,
		controller: controller,
		client:     orClient,
	}
}

package clusterrbac

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

type Client struct {
	manager    manager.Manager
	controller controller.Controller
	client     ReportClient
}

func (e *Client) StartWatching(ctx context.Context) error {
	return e.controller.Watch(source.Kind(e.manager.GetCache(), &v1alpha1.ClusterRbacAssessmentReport{}, &handler.TypedFuncs[*v1alpha1.ClusterRbacAssessmentReport, reconcile.Request]{
		CreateFunc: func(ctx context.Context, event event.TypedCreateEvent[*v1alpha1.ClusterRbacAssessmentReport], _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			err := e.client.GenerateReport(ctx, event.Object)
			if err != nil {
				log.Printf("[ERROR] ClusterRbacAssessmentReport: Failed to process report %s; %s", event.Object.Name, err)
			}
		},
		UpdateFunc: func(ctx context.Context, event event.TypedUpdateEvent[*v1alpha1.ClusterRbacAssessmentReport], _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			err := e.client.GenerateReport(ctx, event.ObjectNew)
			if err != nil {
				log.Printf("[ERROR] ClusterRbacAssessmentReport: Failed to process report %s; %s", event.ObjectNew.Name, err)
			}
		},
		DeleteFunc: func(ctx context.Context, event event.TypedDeleteEvent[*v1alpha1.ClusterRbacAssessmentReport], _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			err := e.client.DeleteReport(ctx, event.Object)
			if err != nil {
				log.Printf("[ERROR] ClusterRbacAssessmentReport: Failed to delete report %s; %s", event.Object.Name, err)
			}
		},
	}))
}

func NewClient(mgr manager.Manager, controller controller.Controller, rclient ReportClient) *Client {
	return &Client{
		manager:    mgr,
		controller: controller,
		client:     rclient,
	}
}

package auditr

import (
	"log"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/trivy-operator/pkg/generated/informers/externalversions"
	"github.com/kyverno/kyverno/pkg/client/clientset/versioned/typed/policyreport/v1alpha2"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type Client struct {
	client                versioned.Interface
	polrClient            *PolicyReportClient
	restartWatchOnFailure time.Duration
}

func (e *Client) StartWatching(ctx context.Context) {
	for {
		e.watch(ctx)
		time.Sleep(e.restartWatchOnFailure)
	}
}

func (e *Client) watch(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)

	factory := externalversions.NewFilteredSharedInformerFactory(e.client, 0, corev1.NamespaceAll, nil)

	informer := factory.Aquasecurity().V1alpha1().ConfigAuditReports().Informer()

	informer.SetWatchErrorHandler(func(_ *cache.Reflector, _ error) {
		cancel()

		log.Println("[WARNING] Watch ConfigAuditReport failed - restarting")
	})

	go e.handleCRDRegistration(ctx, informer, "ConfigAuditReport")

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if report, ok := obj.(*v1alpha1.ConfigAuditReport); ok {
				err := e.polrClient.GenerateReport(ctx, report)
				if err != nil {
					log.Printf("[ERROR] ConfigAuditReport: Failed to process report %s; %s", report.Name, err)
				}
			}
		},
		UpdateFunc: func(oldObj interface{}, obj interface{}) {
			if report, ok := obj.(*v1alpha1.ConfigAuditReport); ok {
				err := e.polrClient.GenerateReport(ctx, report)
				if err != nil {
					log.Printf("[ERROR] ConfigAuditReport: Failed to process report %s; %s", report.Name, err)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			if report, ok := obj.(*v1alpha1.ConfigAuditReport); ok {
				err := e.polrClient.DeleteReport(ctx, report)
				if err != nil {
					log.Printf("[ERROR] ConfigAuditReport: Failed to delete report %s; %s", report.Name, err)
				}
			}
		},
	})

	informer.Run(ctx.Done())
}

func (e *Client) handleCRDRegistration(ctx context.Context, informer cache.SharedIndexInformer, crd string) {
	ticker := time.NewTicker(e.restartWatchOnFailure)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if informer.HasSynced() {
				log.Printf("[INFO] Resource registered: %s\n", crd)
				return
			}
		}
	}
}

func NewClient(client versioned.Interface, polrClient v1alpha2.Wgpolicyk8sV1alpha2Interface, restartWatchOnFailure time.Duration) *Client {
	return &Client{
		client:                client,
		polrClient:            NewPolicyReportClient(polrClient),
		restartWatchOnFailure: restartWatchOnFailure,
	}
}

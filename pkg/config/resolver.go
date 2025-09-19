package config

import (
	"context"
	"time"

	orv1alpha1 "github.com/openreports/reports-api/pkg/client/clientset/versioned/typed/openreports.io/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/auditr"
	auditror "github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/auditr/openreports"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/clusterinfra"
	clusterinfraor "github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/clusterinfra/openreports"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/clusterrbac"
	clusterrbacor "github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/clusterrbac/openreports"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/clustervulnr"
	clustervulnror "github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/clustervulnr/openreports"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/compliance"
	complianceor "github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/compliance/openreports"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/exposedsecret"
	exposedsecretor "github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/exposedsecret/openreports"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/infra"
	infraor "github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/infra/openreports"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/kubebench"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/rbac"
	rbacor "github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/rbac/openreports"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/vulnr"
	vulnror "github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/vulnr/openreports"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/client/clientset/versioned/typed/policyreport/v1alpha2"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/server"
)

// Resolver manages dependencies
type Resolver struct {
	config             *Config
	crdClient          dynamic.ResourceInterface
	polrClient         *v1alpha2.Wgpolicyk8sV1alpha2Client
	orClient           *orv1alpha1.OpenreportsV1alpha1Client
	k8sConfig          *rest.Config
	auditrClient       *auditr.Client
	vulnrClient        vulnr.Client
	clustervulnrClient clustervulnr.Client
	complianceClient   *compliance.Client
	rbacClient         *rbac.Client
	clusterrbacClient  *clusterrbac.Client
	secretClient       *exposedsecret.Client
	infraClient        *infra.Client
	clusterInfraClient *clusterinfra.Client
	kubeBenchClient    *kubebench.Client
	mgr                manager.Manager
}

func (r *Resolver) CRDsClient() (dynamic.ResourceInterface, error) {
	if r.crdClient != nil {
		return r.crdClient, nil
	}

	client, err := dynamic.NewForConfig(r.k8sConfig)
	if err != nil {
		return nil, err
	}

	crd := client.Resource(schema.GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
	})

	r.crdClient = crd

	return crd, nil
}

func (r *Resolver) Server(client dynamic.ResourceInterface) *server.Server {
	return server.New(client, r.config.Server.Port)
}

func (r *Resolver) polrAPI() *v1alpha2.Wgpolicyk8sV1alpha2Client {
	if r.polrClient != nil {
		return r.polrClient
	}
	client, err := v1alpha2.NewForConfig(r.k8sConfig)
	if err != nil {
		panic(err)
	}

	r.polrClient = client

	return client
}

func (r *Resolver) orAPI() *orv1alpha1.OpenreportsV1alpha1Client {
	if r.orClient != nil {
		return r.orClient
	}
	client, err := orv1alpha1.NewForConfig(r.k8sConfig)
	if err != nil {
		panic(err)
	}

	r.orClient = client

	return client
}

func (r *Resolver) Manager() (manager.Manager, error) {
	if r.mgr != nil {
		return r.mgr, nil
	}

	schema := runtime.NewScheme()

	v1alpha1.AddToScheme(schema)

	mgr, err := manager.New(r.k8sConfig, manager.Options{
		Scheme: schema,
		Metrics: metricserver.Options{
			BindAddress: "0",
		},
	})
	if err != nil {
		return nil, err
	}

	r.mgr = mgr

	return r.mgr, nil
}

// ConfigAuditReportClient resolver method
func (r *Resolver) ConfigAuditReportClient() (*auditr.Client, error) {
	if r.auditrClient != nil {
		return r.auditrClient, nil
	}

	mgr, err := r.Manager()
	if err != nil {
		return nil, err
	}

	contr, err := controller.New("configaudit", mgr, controller.Options{
		CacheSyncTimeout: time.Duration(r.config.ConfigAuditReports.Timeout) * time.Minute,
		Reconciler: reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})
	if err != nil {
		return nil, err
	}

	var client auditr.ReportClient

	if r.config.OpenReport.Enabled {
		client = auditror.NewReportClient(r.orAPI(), r.config.VulnerabilityReports.ApplyLabels)
	} else {
		client = auditr.NewReportClient(r.polrAPI(), r.config.VulnerabilityReports.ApplyLabels)
	}

	r.auditrClient = auditr.NewClient(mgr, contr, client)

	return r.auditrClient, nil
}

// VulnerabilityReportClient resolver method
func (r *Resolver) VulnerabilityReportClient() (vulnr.Client, error) {
	if r.vulnrClient != nil {
		return r.vulnrClient, nil
	}

	mgr, err := r.Manager()
	if err != nil {
		return nil, err
	}

	contr, err := controller.New("vulnerability", mgr, controller.Options{
		CacheSyncTimeout: time.Duration(r.config.VulnerabilityReports.Timeout) * time.Minute,
		Reconciler: reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})
	if err != nil {
		return nil, err
	}

	var client vulnr.ReportClient

	if r.config.OpenReport.Enabled {
		client = vulnror.NewReportClient(r.orAPI(), r.config.VulnerabilityReports.ApplyLabels)
	} else {
		client = vulnr.NewReportClient(r.polrAPI(), r.config.VulnerabilityReports.ApplyLabels)
	}

	r.vulnrClient = vulnr.NewClient(mgr, contr, client)

	return r.vulnrClient, nil
}

// ClusterVulnerabilityReportClient resolver method
func (r *Resolver) ClusterVulnerabilityReportClient() (clustervulnr.Client, error) {
	if r.clustervulnrClient != nil {
		return r.clustervulnrClient, nil
	}

	mgr, err := r.Manager()
	if err != nil {
		return nil, err
	}

	contr, err := controller.New("clustervulnerability", mgr, controller.Options{
		CacheSyncTimeout: time.Duration(r.config.ClusterVulnerabilityReports.Timeout) * time.Minute,
		Reconciler: reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})
	if err != nil {
		return nil, err
	}

	var client clustervulnr.ReportClient

	if r.config.OpenReport.Enabled {
		client = clustervulnror.NewReportClient(r.orAPI(), r.config.ClusterVulnerabilityReports.ApplyLabels)
	} else {
		client = clustervulnr.NewReportClient(r.polrAPI(), r.config.ClusterVulnerabilityReports.ApplyLabels)
	}

	r.clustervulnrClient = clustervulnr.NewClient(mgr, contr, client)

	return r.clustervulnrClient, nil
}

// ComplianceReportClient resolver method
func (r *Resolver) ComplianceReportClient() (*compliance.Client, error) {
	if r.complianceClient != nil {
		return r.complianceClient, nil
	}

	mgr, err := r.Manager()
	if err != nil {
		return nil, err
	}

	contr, err := controller.New("compliance", mgr, controller.Options{
		CacheSyncTimeout: time.Duration(r.config.ComplianceReports.Timeout) * time.Minute,
		Reconciler: reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})
	if err != nil {
		return nil, err
	}

	var client compliance.ReportClient

	if r.config.OpenReport.Enabled {
		client = complianceor.NewReportClient(r.orAPI(), r.config.ComplianceReports.ApplyLabels)
	} else {
		client = compliance.NewReportClient(r.polrAPI(), r.config.ComplianceReports.ApplyLabels)
	}

	r.complianceClient = compliance.NewClient(mgr, contr, client)

	return r.complianceClient, nil
}

// RbacAssessmentReportClient resolver method
func (r *Resolver) RbacAssessmentReportClient() (*rbac.Client, error) {
	if r.rbacClient != nil {
		return r.rbacClient, nil
	}

	mgr, err := r.Manager()
	if err != nil {
		return nil, err
	}

	contr, err := controller.New("rbacassessment", mgr, controller.Options{
		CacheSyncTimeout: time.Duration(r.config.RbacAssessmentReports.Timeout) * time.Minute,
		Reconciler: reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})
	if err != nil {
		return nil, err
	}

	var client rbac.ReportClient

	if r.config.OpenReport.Enabled {
		client = rbacor.NewReportClient(r.orAPI(), r.config.RbacAssessmentReports.ApplyLabels)
	} else {
		client = rbac.NewReportClient(r.polrAPI(), r.config.RbacAssessmentReports.ApplyLabels)
	}

	r.rbacClient = rbac.NewClient(mgr, contr, client)

	return r.rbacClient, nil
}

// ClusterRbacAssessmentReportClient resolver method
func (r *Resolver) ClusterRbacAssessmentReportClient() (*clusterrbac.Client, error) {
	if r.clusterrbacClient != nil {
		return r.clusterrbacClient, nil
	}

	mgr, err := r.Manager()
	if err != nil {
		return nil, err
	}

	contr, err := controller.New("clusterrbacassessment", mgr, controller.Options{
		CacheSyncTimeout: time.Duration(r.config.RbacAssessmentReports.Timeout) * time.Minute,
		Reconciler: reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})
	if err != nil {
		return nil, err
	}

	var client clusterrbac.ReportClient

	if r.config.OpenReport.Enabled {
		client = clusterrbacor.NewReportClient(r.orAPI(), r.config.RbacAssessmentReports.ApplyLabels)
	} else {
		client = clusterrbac.NewReportClient(r.polrAPI(), r.config.RbacAssessmentReports.ApplyLabels)
	}

	r.clusterrbacClient = clusterrbac.NewClient(mgr, contr, client)

	return r.clusterrbacClient, nil
}

// RbacAssessmentReportClient resolver method
func (r *Resolver) ExposedSecretReportClient() (*exposedsecret.Client, error) {
	if r.secretClient != nil {
		return r.secretClient, nil
	}

	mgr, err := r.Manager()
	if err != nil {
		return nil, err
	}

	contr, err := controller.New("exposedsecret", mgr, controller.Options{
		CacheSyncTimeout: time.Duration(r.config.ExposedSecretReports.Timeout) * time.Minute,
		Reconciler: reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})
	if err != nil {
		return nil, err
	}

	var client exposedsecret.ReportClient

	if r.config.OpenReport.Enabled {
		client = exposedsecretor.NewReportClient(r.orAPI(), r.config.ExposedSecretReports.ApplyLabels)
	} else {
		client = exposedsecret.NewReportClient(r.polrAPI(), r.config.ExposedSecretReports.ApplyLabels)
	}

	r.secretClient = exposedsecret.NewClient(mgr, contr, client)

	return r.secretClient, nil
}

// CISKubeBenchReportClient resolver method
func (r *Resolver) CISKubeBenchReportClient() (*kubebench.Client, error) {
	if r.kubeBenchClient != nil {
		return r.kubeBenchClient, nil
	}

	polrClient := r.polrAPI()

	mgr, err := r.Manager()
	if err != nil {
		return nil, err
	}

	contr, err := controller.New("ciskubebench", mgr, controller.Options{
		CacheSyncTimeout: time.Duration(r.config.CISKubeBenchReports.Timeout) * time.Minute,
		Reconciler: reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})
	if err != nil {
		return nil, err
	}

	r.kubeBenchClient = kubebench.NewClient(mgr, contr, polrClient, r.config.CISKubeBenchReports.ApplyLabels)

	return r.kubeBenchClient, nil
}

// InfraAssessmentReportClient resolver method
func (r *Resolver) InfraAssessmentReportClient() (*infra.Client, error) {
	if r.infraClient != nil {
		return r.infraClient, nil
	}

	mgr, err := r.Manager()
	if err != nil {
		return nil, err
	}

	contr, err := controller.New("infraassessment", mgr, controller.Options{
		CacheSyncTimeout: time.Duration(r.config.InfraAssessmentReports.Timeout) * time.Minute,
		Reconciler: reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})
	if err != nil {
		return nil, err
	}

	var client infra.ReportClient

	if r.config.OpenReport.Enabled {
		client = infraor.NewReportClient(r.orAPI(), r.config.InfraAssessmentReports.ApplyLabels)
	} else {
		client = infra.NewReportClient(r.polrAPI(), r.config.InfraAssessmentReports.ApplyLabels)
	}

	r.infraClient = infra.NewClient(mgr, contr, client)

	return r.infraClient, nil
}

// ClusterInfraAssessmentReportClient resolver method
func (r *Resolver) ClusterInfraAssessmentReportClient() (*clusterinfra.Client, error) {
	if r.clusterInfraClient != nil {
		return r.clusterInfraClient, nil
	}

	mgr, err := r.Manager()
	if err != nil {
		return nil, err
	}

	contr, err := controller.New("clusterinfraassessment", mgr, controller.Options{
		CacheSyncTimeout: time.Duration(r.config.ClusterInfraAssessmentReports.Timeout) * time.Minute,
		Reconciler: reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}),
	})
	if err != nil {
		return nil, err
	}

	var client clusterinfra.ReportClient

	if r.config.OpenReport.Enabled {
		client = clusterinfraor.NewReportClient(r.orAPI(), r.config.ClusterInfraAssessmentReports.ApplyLabels)
	} else {
		client = clusterinfra.NewReportClient(r.polrAPI(), r.config.ClusterInfraAssessmentReports.ApplyLabels)
	}

	r.clusterInfraClient = clusterinfra.NewClient(mgr, contr, client)

	return r.clusterInfraClient, nil
}

// NewResolver constructor function
func NewResolver(config *Config, k8sConfig *rest.Config) Resolver {
	return Resolver{
		config:    config,
		k8sConfig: k8sConfig,
	}
}

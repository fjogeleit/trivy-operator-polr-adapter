package config

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/auditr"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/clusterrbac"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/compliance"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/exposedsecret"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/infra"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/kubebench"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/rbac"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/vulnr"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/apis/aquasecurity/v1alpha1"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/client/clientset/versioned/typed/policyreport/v1alpha2"
)

// Resolver manages dependencies
type Resolver struct {
	config            *Config
	polrClient        *v1alpha2.Wgpolicyk8sV1alpha2Client
	k8sConfig         *rest.Config
	auditrClient      *auditr.Client
	vulnrClient       *vulnr.Client
	complianceClient  *compliance.Client
	rbacClient        *rbac.Client
	clusterrbacClient *clusterrbac.Client
	secretClient      *exposedsecret.Client
	infraClient       *infra.Client
	kubeBenchClient   *kubebench.Client
	mgr               manager.Manager
}

func (r *Resolver) polrAPI() (*v1alpha2.Wgpolicyk8sV1alpha2Client, error) {
	if r.polrClient != nil {
		return r.polrClient, nil
	}
	client, err := v1alpha2.NewForConfig(r.k8sConfig)
	if err != nil {
		return nil, err
	}

	r.polrClient = client

	return client, nil
}

func (r *Resolver) Manager() (manager.Manager, error) {
	if r.mgr != nil {
		return r.mgr, nil
	}

	schema := runtime.NewScheme()

	v1alpha1.AddToScheme(schema)

	mgr, err := manager.New(r.k8sConfig, manager.Options{
		Scheme:             schema,
		MetricsBindAddress: "0",
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

	polrClient, err := r.polrAPI()
	if err != nil {
		return nil, err
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

	r.auditrClient = auditr.NewClient(contr, polrClient, r.config.ConfigAuditReports.ApplyLabels)

	return r.auditrClient, nil
}

// VulnerabilityReportClient resolver method
func (r *Resolver) VulnerabilityReportClient() (*vulnr.Client, error) {
	if r.vulnrClient != nil {
		return r.vulnrClient, nil
	}

	polrClient, err := r.polrAPI()
	if err != nil {
		return nil, err
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

	r.vulnrClient = vulnr.NewClient(contr, polrClient, r.config.VulnerabilityReports.ApplyLabels)

	return r.vulnrClient, nil
}

// ComplianceReportClient resolver method
func (r *Resolver) ComplianceReportClient() (*compliance.Client, error) {
	if r.complianceClient != nil {
		return r.complianceClient, nil
	}

	polrClient, err := r.polrAPI()
	if err != nil {
		return nil, err
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

	r.complianceClient = compliance.NewClient(contr, polrClient, r.config.ComplianceReports.ApplyLabels)

	return r.complianceClient, nil
}

// RbacAssessmentReportClient resolver method
func (r *Resolver) RbacAssessmentReportClient() (*rbac.Client, error) {
	if r.rbacClient != nil {
		return r.rbacClient, nil
	}

	polrClient, err := r.polrAPI()
	if err != nil {
		return nil, err
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

	r.rbacClient = rbac.NewClient(contr, polrClient, r.config.RbacAssessmentReports.ApplyLabels)

	return r.rbacClient, nil
}

// ClusterRbacAssessmentReportClient resolver method
func (r *Resolver) ClusterRbacAssessmentReportClient() (*clusterrbac.Client, error) {
	if r.clusterrbacClient != nil {
		return r.clusterrbacClient, nil
	}

	polrClient, err := r.polrAPI()
	if err != nil {
		return nil, err
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

	r.clusterrbacClient = clusterrbac.NewClient(contr, polrClient, r.config.RbacAssessmentReports.ApplyLabels)

	return r.clusterrbacClient, nil
}

// RbacAssessmentReportClient resolver method
func (r *Resolver) ExposedSecretReportClient() (*exposedsecret.Client, error) {
	if r.secretClient != nil {
		return r.secretClient, nil
	}

	polrClient, err := r.polrAPI()
	if err != nil {
		return nil, err
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

	r.secretClient = exposedsecret.NewClient(contr, polrClient, r.config.ExposedSecretReports.ApplyLabels)

	return r.secretClient, nil
}

// CISKubeBenchReportClient resolver method
func (r *Resolver) CISKubeBenchReportClient() (*kubebench.Client, error) {
	if r.kubeBenchClient != nil {
		return r.kubeBenchClient, nil
	}

	polrClient, err := r.polrAPI()
	if err != nil {
		return nil, err
	}

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

	r.kubeBenchClient = kubebench.NewClient(contr, polrClient, r.config.CISKubeBenchReports.ApplyLabels)

	return r.kubeBenchClient, nil
}

// InfraAssessmentReportClient resolver method
func (r *Resolver) InfraAssessmentReportClient() (*infra.Client, error) {
	if r.infraClient != nil {
		return r.infraClient, nil
	}

	polrClient, err := r.polrAPI()
	if err != nil {
		return nil, err
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

	r.infraClient = infra.NewClient(contr, polrClient, r.config.ExposedSecretReports.ApplyLabels)

	return r.infraClient, nil
}

// NewResolver constructor function
func NewResolver(config *Config, k8sConfig *rest.Config) Resolver {
	return Resolver{
		config:    config,
		k8sConfig: k8sConfig,
	}
}

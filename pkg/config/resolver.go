package config

import (
	"time"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/auditr"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/compliance"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/kubebench"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/adapters/vulnr"

	"github.com/aquasecurity/trivy-operator/pkg/generated/clientset/versioned"
	"github.com/kyverno/kyverno/pkg/client/clientset/versioned/typed/policyreport/v1alpha2"
	"k8s.io/client-go/rest"
)

// Resolver manages dependencies
type Resolver struct {
	config           *Config
	trivyClient      *versioned.Clientset
	polrClient       *v1alpha2.Wgpolicyk8sV1alpha2Client
	k8sConfig        *rest.Config
	auditrClient     *auditr.Client
	vulnClient       *vulnr.Client
	kubebenchClient  *kubebench.Client
	complianceClient *compliance.Client
}

func (r *Resolver) trivyAPI() (*versioned.Clientset, error) {
	if r.trivyClient != nil {
		return r.trivyClient, nil
	}
	client, err := versioned.NewForConfig(r.k8sConfig)
	if err != nil {
		return nil, err
	}

	r.trivyClient = client

	return client, nil
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
func (r *Resolver) k8sClients() (*versioned.Clientset, *v1alpha2.Wgpolicyk8sV1alpha2Client, error) {
	client, err := r.trivyAPI()
	if err != nil {
		return nil, nil, err
	}
	polrClient, err := r.polrAPI()
	if err != nil {
		return nil, nil, err
	}

	return client, polrClient, nil
}

// VulnerabilityReportClient resolver method
func (r *Resolver) VulnerabilityReportClient() (*vulnr.Client, error) {
	if r.vulnClient != nil {
		return r.vulnClient, nil
	}

	client, polrClient, err := r.k8sClients()
	if err != nil {
		return nil, err
	}

	vulnClient := vulnr.NewClient(client, polrClient, 5*time.Second)

	r.vulnClient = vulnClient

	return vulnClient, nil
}

// ConfigAuditReportClient resolver method
func (r *Resolver) ConfigAuditReportClient() (*auditr.Client, error) {
	if r.auditrClient != nil {
		return r.auditrClient, nil
	}

	client, polrClient, err := r.k8sClients()
	if err != nil {
		return nil, err
	}

	auditrClient := auditr.NewClient(client, polrClient, 5*time.Second)

	r.auditrClient = auditrClient

	return auditrClient, nil
}

// CISKubeBenchReportClient resolver method
func (r *Resolver) CISKubeBenchReportClient() (*kubebench.Client, error) {
	if r.kubebenchClient != nil {
		return r.kubebenchClient, nil
	}

	client, polrClient, err := r.k8sClients()
	if err != nil {
		return nil, err
	}

	kubebenchClient := kubebench.NewClient(client, polrClient, 5*time.Second)

	r.kubebenchClient = kubebenchClient

	return kubebenchClient, nil
}

// CompliaceReportClient resolver method
func (r *Resolver) CompliaceReportClient() (*compliance.Client, error) {
	if r.complianceClient != nil {
		return r.complianceClient, nil
	}

	client, polrClient, err := r.k8sClients()
	if err != nil {
		return nil, err
	}

	complianceClient := compliance.NewClient(client, polrClient, 5*time.Second)

	r.complianceClient = complianceClient

	return complianceClient, nil
}

// NewResolver constructor function
func NewResolver(config *Config, k8sConfig *rest.Config) Resolver {
	return Resolver{
		config:    config,
		k8sConfig: k8sConfig,
	}
}

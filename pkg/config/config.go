package config

// VulnerabilityReports configuration
type VulnerabilityReports struct {
	Enabled bool `mapstructure:"enabled"`
}

// ConfigAuditReports configuration
type ConfigAuditReports struct {
	Enabled bool `mapstructure:"enabled"`
}

// CISKubeBenchReports configuration
type CISKubeBenchReports struct {
	Enabled bool `mapstructure:"enabled"`
}

// ComplianceReports configuration
type ComplianceReports struct {
	Enabled bool `mapstructure:"enabled"`
}

// RbacAssessmentReports configuration
type RbacAssessmentReports struct {
	Enabled bool `mapstructure:"enabled"`
}

// ExposedSecretReports configuration
type ExposedSecretReports struct {
	Enabled bool `mapstructure:"enabled"`
}

// Config of the Tracee Adapter
type Config struct {
	Kubeconfig            string                `mapstructure:"kubeconfig"`
	VulnerabilityReports  VulnerabilityReports  `mapstructure:"vulnerabilityReports"`
	ConfigAuditReports    ConfigAuditReports    `mapstructure:"configAuditReports"`
	CISKubeBenchReports   CISKubeBenchReports   `mapstructure:"cisKubeBenchReports"`
	ComplianceReports     ComplianceReports     `mapstructure:"complianceReports"`
	RbacAssessmentReports RbacAssessmentReports `mapstructure:"rbacAssessmentReports"`
	ExposedSecretReports  ExposedSecretReports  `mapstructure:"exposedSecretReports"`
}

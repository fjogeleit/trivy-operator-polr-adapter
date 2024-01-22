package config

// Server configuration
type Server struct {
	Port int `mapstructure:"port"`
}

// VulnerabilityReports configuration
type ReportConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	Timeout     int      `mapstructure:"timeout"`
	ApplyLabels []string `mapstructure:"applyLabels"`
}

// Config of the Tracee Adapter
type Config struct {
	Kubeconfig                    string       `mapstructure:"kubeconfig"`
	Server                        Server       `mapstructure:"server"`
	VulnerabilityReports          ReportConfig `mapstructure:"vulnerabilityReports"`
	ClusterVulnerabilityReports   ReportConfig `mapstructure:"clusterVulnerabilityReports"`
	ConfigAuditReports            ReportConfig `mapstructure:"configAuditReports"`
	CISKubeBenchReports           ReportConfig `mapstructure:"cisKubeBenchReports"`
	ComplianceReports             ReportConfig `mapstructure:"complianceReports"`
	RbacAssessmentReports         ReportConfig `mapstructure:"rbacAssessmentReports"`
	ExposedSecretReports          ReportConfig `mapstructure:"exposedSecretReports"`
	InfraAssessmentReports        ReportConfig `mapstructure:"infraAssessmentReports"`
	ClusterInfraAssessmentReports ReportConfig `mapstructure:"clusterInfraAssessmentReports"`
}

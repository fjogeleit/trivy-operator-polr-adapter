package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/config"
)

func loadConfig(cmd *cobra.Command) (*config.Config, error) {
	v := viper.New()

	cfgFile := ""

	configFlag := cmd.Flags().Lookup("config")
	if configFlag != nil {
		cfgFile = configFlag.Value.String()
	}

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.AddConfigPath(".")
		v.SetConfigName("config")
	}

	v.AutomaticEnv()
	v.ReadInConfig()

	if flag := cmd.Flags().Lookup("kubeconfig"); flag != nil {
		v.BindPFlag("kubeconfig", flag)
	}

	if flag := cmd.Flags().Lookup("enable-vulnerability"); flag != nil {
		v.BindPFlag("vulnerabilityReports.enabled", flag)
	}
	if flag := cmd.Flags().Lookup("enable-config-audit"); flag != nil {
		v.BindPFlag("configAuditReports.enabled", flag)
	}
	if flag := cmd.Flags().Lookup("enable-kube-bench"); flag != nil {
		v.BindPFlag("cisKubeBenchReports.enabled", flag)
	}
	if flag := cmd.Flags().Lookup("enable-compliancer"); flag != nil {
		v.BindPFlag("cisKubeBenchReports.enabled", flag)
	}
	if flag := cmd.Flags().Lookup("enable-rbac-assessment"); flag != nil {
		v.BindPFlag("rbacAssessmentReports.enabled", flag)
	}
	if flag := cmd.Flags().Lookup("enable-exposed-secrets"); flag != nil {
		v.BindPFlag("exposedSecretReports.enabled", flag)
	}
	if flag := cmd.Flags().Lookup("enable-infra-assessment"); flag != nil {
		v.BindPFlag("infraAssessmentReports.enabled", flag)
	}
	if flag := cmd.Flags().Lookup("enable-cluster-infra-assessment"); flag != nil {
		v.BindPFlag("clusterInfraAssessmentReports.enabled", flag)
	}
	if flag := cmd.Flags().Lookup("port"); flag != nil {
		v.BindPFlag("server.port", flag)
	}

	c := &config.Config{}

	err := v.Unmarshal(c)

	return c, err
}

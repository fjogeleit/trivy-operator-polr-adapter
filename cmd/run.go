package cmd

import (
	"flag"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/config"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func newRunCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run configured Adapters",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := loadConfig(cmd)
			if err != nil {
				return err
			}

			var k8sConfig *rest.Config
			if c.Kubeconfig != "" {
				k8sConfig, err = clientcmd.BuildConfigFromFlags("", c.Kubeconfig)
			} else {
				k8sConfig, err = rest.InClusterConfig()
			}
			if err != nil {
				return err
			}

			resolver := config.NewResolver(c, k8sConfig)

			if c.ConfigAuditReports.Enabled {
				auditrClient, err := resolver.ConfigAuditReportClient()
				if err != nil {
					return err
				}

				err = auditrClient.StartWatching(cmd.Context())
				if err != nil {
					return err
				}
			}

			if c.VulnerabilityReports.Enabled {
				vulnrClient, err := resolver.VulnerabilityReportClient()
				if err != nil {
					return err
				}

				err = vulnrClient.StartWatching(cmd.Context())
				if err != nil {
					return err
				}
			}

			if c.ComplianceReports.Enabled {
				complianceClient, err := resolver.ComplianceReportClient()
				if err != nil {
					return err
				}

				err = complianceClient.StartWatching(cmd.Context())
				if err != nil {
					return err
				}
			}

			if c.RbacAssessmentReports.Enabled {
				rbacClient, err := resolver.RbacAssessmentReportClient()
				if err != nil {
					return err
				}

				err = rbacClient.StartWatching(cmd.Context())
				if err != nil {
					return err
				}

				clusterrbacClient, err := resolver.ClusterRbacAssessmentReportClient()
				if err != nil {
					return err
				}

				err = clusterrbacClient.StartWatching(cmd.Context())
				if err != nil {
					return err
				}
			}

			if c.ExposedSecretReports.Enabled {
				secretClient, err := resolver.ExposedSecretReportClient()
				if err != nil {
					return err
				}

				err = secretClient.StartWatching(cmd.Context())
				if err != nil {
					return err
				}
			}

			if c.CISKubeBenchReports.Enabled {
				kubeBenchClient, err := resolver.CISKubeBenchReportClient()
				if err != nil {
					return err
				}

				err = kubeBenchClient.StartWatching(cmd.Context())
				if err != nil {
					return err
				}
			}

			mgr, err := resolver.Manager()
			if err != nil {
				return err
			}

			return mgr.Start(cmd.Context())
		},
	}

	// For local usage
	cmd.PersistentFlags().StringP("kubeconfig", "k", "", "absolute path to the kubeconfig file")
	cmd.PersistentFlags().StringP("config", "c", "", "target configuration file")

	cmd.PersistentFlags().Bool("enable-vulnerability", false, "Enable the transformation of VulnerabilityReports into PolicyReports")
	cmd.PersistentFlags().Bool("enable-config-audit", false, "Enable the transformation of ConfigAuditReports into PolicyReports")
	cmd.PersistentFlags().Bool("enable-kube-bench", false, "Enable the transformation of CISKubeBenchReports into ClusterPolicyReports")
	cmd.PersistentFlags().Bool("enable-compliance", false, "Enable the transformation of ClusterComplianceDetailReport into ClusterPolicyReports")
	cmd.PersistentFlags().Bool("enable-rbac-assessment", false, "Enable the transformation of RbacAssessmentReport into PolicyReports")
	cmd.PersistentFlags().Bool("enable-exposed-secrets", false, "Enable the transformation of ExposedSecretReport into PolicyReports")

	flag.Parse()

	return cmd
}

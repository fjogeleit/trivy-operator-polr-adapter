package cmd

import (
	"flag"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/config"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
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

			g := &errgroup.Group{}

			if c.VulnerabilityReports.Enabled {
				vulnrClient, err := resolver.VulnerabilityReportClient()
				if err != nil {
					return err
				}
				g.Go(func() error {
					vulnrClient.StartWatching(cmd.Context())
					return nil
				})
			}

			if c.ConfigAuditReports.Enabled {
				auditrClient, err := resolver.ConfigAuditReportClient()
				if err != nil {
					return err
				}
				g.Go(func() error {
					auditrClient.StartWatching(cmd.Context())
					return nil
				})
			}

			if c.CISKubeBenchReports.Enabled {
				kubebenchClient, err := resolver.CISKubeBenchReportClient()
				if err != nil {
					return err
				}
				g.Go(func() error {
					kubebenchClient.StartWatching(cmd.Context())
					return nil
				})
			}

			if c.ComplianceReports.Enabled {
				complianceClient, err := resolver.CompliaceReportClient()
				if err != nil {
					return err
				}
				g.Go(func() error {
					complianceClient.StartWatching(cmd.Context())
					return nil
				})
			}

			return g.Wait()
		},
	}

	// For local usage
	cmd.PersistentFlags().StringP("kubeconfig", "k", "", "absolute path to the kubeconfig file")
	cmd.PersistentFlags().StringP("config", "c", "", "target configuration file")

	cmd.PersistentFlags().Bool("enable-vulnerability", false, "Enable the transformation of VulnerabilityReports into PolicyReports")
	cmd.PersistentFlags().Bool("enable-config-audit", false, "Enable the transformation of ConfigAuditReports into PolicyReports")
	cmd.PersistentFlags().Bool("enable-kube-bench", false, "Enable the transformation of CISKubeBenchReports into ClusterPolicyReports")
	cmd.PersistentFlags().Bool("enable-compliance", false, "Enable the transformation of ClusterComplianceDetailReport into ClusterPolicyReports")

	flag.Parse()

	return cmd
}

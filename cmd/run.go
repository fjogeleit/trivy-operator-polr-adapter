package cmd

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/config"
	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/crd"
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

			crdsClient, err := resolver.CRDsClient()
			if err != nil {
				return err
			}

			srv := resolver.Server(crdsClient)
			if err != nil {
				return err
			}

			go func() {
				fmt.Printf("[INFO] start server on port %d\n", c.Server.Port)
				if err := srv.Start(); err != nil {
					fmt.Println("[ERROR] failed to start server")
				}
			}()

			for {
				err := crd.EnsurePolicyReportAvailable(cmd.Context(), crdsClient)
				if err == nil {
					break
				}

				log.Printf("[ERROR] %s\n", err)
				time.Sleep(time.Minute)
			}

			if c.ConfigAuditReports.Enabled {
				fmt.Println("[INFO] ConfigAuditReports enabled")
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
				fmt.Println("[INFO] VulnerabilityReports enabled")
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
				fmt.Println("[INFO] ComplianceReports enabled")
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
				fmt.Println("[INFO] RbacAssessmentReports enabled")
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
				fmt.Println("[INFO] ExposedSecretReports enabled")
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
				fmt.Println("[INFO] CISKubeBenchReports enabled")
				kubeBenchClient, err := resolver.CISKubeBenchReportClient()
				if err != nil {
					return err
				}

				err = kubeBenchClient.StartWatching(cmd.Context())
				if err != nil {
					return err
				}
			}

			if c.InfraAssessmentReports.Enabled {
				fmt.Println("[INFO] InfraAssessmentReportClient enabled")
				infraClient, err := resolver.InfraAssessmentReportClient()
				if err != nil {
					return err
				}

				err = infraClient.StartWatching(cmd.Context())
				if err != nil {
					return err
				}
			}

			if c.ClusterInfraAssessmentReports.Enabled {
				fmt.Println("[INFO] ClusterInfraAssessmentReportClient enabled")
				clusterInfraClient, err := resolver.ClusterInfraAssessmentReportClient()
				if err != nil {
					return err
				}

				err = clusterInfraClient.StartWatching(cmd.Context())
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
	cmd.PersistentFlags().IntP("port", "p", 8080, "Port of the Server")
	cmd.PersistentFlags().StringP("config", "c", "", "target configuration file")

	cmd.PersistentFlags().Bool("enable-vulnerability", false, "Enable the transformation of VulnerabilityReports into PolicyReports")
	cmd.PersistentFlags().Bool("enable-config-audit", false, "Enable the transformation of ConfigAuditReports into PolicyReports")
	cmd.PersistentFlags().Bool("enable-kube-bench", false, "Enable the transformation of CISKubeBenchReports into ClusterPolicyReports")
	cmd.PersistentFlags().Bool("enable-compliance", false, "Enable the transformation of ClusterComplianceDetailReports into ClusterPolicyReports")
	cmd.PersistentFlags().Bool("enable-rbac-assessment", false, "Enable the transformation of RbacAssessmentReports into PolicyReports")
	cmd.PersistentFlags().Bool("enable-exposed-secrets", false, "Enable the transformation of ExposedSecretReports into PolicyReports")
	cmd.PersistentFlags().Bool("enable-infra-assessment", false, "Enable the transformation of InfraAssessmentReports into PolicyReports")
	cmd.PersistentFlags().Bool("enable-cluster-infra-assessment", false, "Enable the transformation of ClusterInfraAssessmentReports into ClusterPolicyReports")

	flag.Parse()

	return cmd
}

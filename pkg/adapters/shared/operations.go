package shared

import (
	"context"
	"fmt"

	pr "github.com/fjogeleit/trivy-operator-polr-adapter/pkg/client/clientset/versioned/typed/policyreport/v1alpha2"
	or "github.com/openreports/reports-api/pkg/client/clientset/versioned/typed/openreports.io/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

func WGPolrCleanup(ctx context.Context, client pr.Wgpolicyk8sV1alpha2Interface, source string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		list, err := client.PolicyReports(v1.NamespaceAll).List(ctx, v1.ListOptions{
			LabelSelector: fmt.Sprintf("trivy-operator.source=%s", source),
		})
		if err != nil {
			return err
		}

		namespaces := map[string]struct{}{}
		for _, polr := range list.Items {
			namespaces[polr.Namespace] = struct{}{}
		}

		for ns := range namespaces {
			err = client.PolicyReports(ns).DeleteCollection(ctx, v1.DeleteOptions{}, v1.ListOptions{
				LabelSelector: fmt.Sprintf("trivy-operator.source=%s", source),
			})
			if err != nil {
				return fmt.Errorf("failed to cleanup config audit reports: %w", err)
			}
		}

		return nil
	})
}

func OpenReportCleanup(ctx context.Context, client or.OpenreportsV1alpha1Interface, source string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		list, err := client.Reports(v1.NamespaceAll).List(ctx, v1.ListOptions{
			LabelSelector: fmt.Sprintf("trivy-operator.source=%s", source),
		})
		if err != nil {
			return err
		}

		namespaces := map[string]struct{}{}
		for _, polr := range list.Items {
			namespaces[polr.Namespace] = struct{}{}
		}

		for ns := range namespaces {
			err = client.Reports(ns).DeleteCollection(ctx, v1.DeleteOptions{}, v1.ListOptions{
				LabelSelector: fmt.Sprintf("trivy-operator.source=%s", source),
			})
			if err != nil {
				return fmt.Errorf("failed to cleanup config audit reports: %w", err)
			}
		}

		return nil
	})
}

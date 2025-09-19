package crd

import (
	"context"
	"errors"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
)

const (
	policyReport        = "policyreports.wgpolicyk8s.io"
	clusterPolicyReport = "clusterpolicyreports.wgpolicyk8s.io"

	report        = "reports.openreports.io"
	clusterReport = "clusterreports.openreports.io"
)

var (
	errPolicyReportNotFound        = errors.New("failed to get PolicyReport CRD, ensure it is installed")
	errClusterPolicyReportNotFound = errors.New("failed to get ClusterPolicyReport CRD, ensure it is installed")

	errReportNotFound        = errors.New("failed to get Report CRD, ensure it is installed")
	errClusterReportNotFound = errors.New("failed to get ClusterReport CRD, ensure it is installed")
)

type Validator = func(ctx context.Context, client dynamic.ResourceInterface) error

func EnsurePolicyReportAvailable(ctx context.Context, client dynamic.ResourceInterface) error {
	_, err := client.Get(ctx, policyReport, v1.GetOptions{})
	if err != nil {
		return errPolicyReportNotFound
	}

	_, err = client.Get(ctx, clusterPolicyReport, v1.GetOptions{})
	if err != nil {
		return errClusterPolicyReportNotFound
	}

	return nil
}

func EnsureOpenReportAvailable(ctx context.Context, client dynamic.ResourceInterface) error {
	_, err := client.Get(ctx, report, v1.GetOptions{})
	if err != nil {
		return errReportNotFound
	}

	_, err = client.Get(ctx, clusterReport, v1.GetOptions{})
	if err != nil {
		return errClusterReportNotFound
	}

	return nil
}

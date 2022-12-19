package shared

import (
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	kindLabel      = "trivy-operator.resource.kind"
	nameLabel      = "trivy-operator.resource.name"
	namespaceLabel = "trivy-operator.resource.namespace"
)

func CreateObjectReference(namespace string, owners []v1.OwnerReference, labels map[string]string) corev1.ObjectReference {
	if len(owners) == 1 {
		ref := owners[0].DeepCopy()

		return corev1.ObjectReference{
			Namespace:  namespace,
			APIVersion: ref.APIVersion,
			Kind:       ref.Kind,
			Name:       ref.Name,
			UID:        ref.UID,
		}
	}
	return corev1.ObjectReference{
		Namespace: labels[namespaceLabel],
		Kind:      labels[kindLabel],
		Name:      labels[nameLabel],
	}
}

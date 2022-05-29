# Trivy Operator PolicyReport Adapter

Install with Helm

```bash
helm repo add trivy-operator-polr-adapter https://fjogeleit.github.io/trivy-operator-polr-adapter
helm install trivy-operator-polr-adapter trivy-operator-polr-adapter/trivy-operator-polr-adapter -n trivy-adapter --create-namespace
```
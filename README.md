# Trivy Operator PolicyReport Adapter

Maps Trivy Operator CRDs into the unified PolicyReport and ClusterPolicyReport from the Kubernetes Policy Working Group. This makes it possible to use tooling like [Policy Reporter](https://github.com/kyverno/policy-reporter) for the different kinds of Trivy Reports.

## Pre Requirements

1. [Trivy Operator](https://github.com/aquasecurity/trivy-operator) with the related CRDs is installed and running
2. [PolicyReport CRDs](https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report/crd/v1alpha2) are installed in your Cluster

## Installation via Helm

```bash
helm repo add trivy-operator-polr-adapter https://fjogeleit.github.io/trivy-operator-polr-adapter
helm install trivy-operator-polr-adapter trivy-operator-polr-adapter/trivy-operator-polr-adapter -n trivy-adapter --create-namespace
```

## Integreted Adapters

### VulnerabilityReports

Maps VulnerabilityReports into PolicyReports with the relation 1:1. The PolicyReport is referenced with the scanned resource like the VulnerabilityReport itself.

```yaml
apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata:
  labels:
    managed-by: trivy-operator-polr-adapter
    trivy-operator.source: VulnerabilityReport
  name: trivy-vuln-polr-nginx-5fbc65fff
  namespace: test
  ownerReferences:
  - apiVersion: apps/v1
    blockOwnerDeletion: false
    controller: true
    kind: ReplicaSet
    name: nginx-5fbc65fff
    uid: 710f2142-7613-4cf5-aef7-dc65306626e2
  resourceVersion: "122118"
  uid: 2ea883ef-c060-4e80-ae34-3f9b527c02bc
results:
- category: Vulnerability Scan
  message: 'apt: integer overflows and underflows while parsing .deb packages'
  policy: CVE-2020-27350
  properties:
    artifact.repository: library/nginx
    artifact.tag: "1.17"
    fixedVersion: 1.8.2.2
    installedVersion: 1.8.2.1
    primaryLink: https://avd.aquasec.com/nvd/cve-2020-27350
    registry.server: index.docker.io
    resource: apt
    score: "5.7"
  resources:
  - apiVersion: apps/v1
    kind: ReplicaSet
    name: nginx-5fbc65fff
    namespace: test
    uid: 710f2142-7613-4cf5-aef7-dc65306626e2
  result: warn
  severity: medium
  source: Trivy Vulnerability
  timestamp:
    nanos: 0
    seconds: 1653395950
summary:
  error: 0
  fail: 109
  pass: 0
  skip: 1
  warn: 166
```

### ConfigAuditReports

Maps ConfigAuditReports into PolicyReports with the relation 1:1. The PolicyReport is referenced with the scanned resource like the ConfigAuditReport itself.

```yaml
apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata:
  labels:
    managed-by: trivy-operator-polr-adapter
    trivy-operator.source: ConfigAuditReport
  name: trivy-audit-polr-nginx-5fbc65fff
  namespace: test
  ownerReferences:
  - apiVersion: apps/v1
    blockOwnerDeletion: false
    controller: true
    kind: ReplicaSet
    name: nginx-5fbc65fff
    uid: 710f2142-7613-4cf5-aef7-dc65306626e2
results:
- category: Kubernetes Security Check
  message: Sysctls can disable security mechanisms or affect all containers on a host,
    and should be disallowed except for an allowed 'safe' subset. A sysctl is considered
    safe if it is namespaced in the container or the Pod, and it is isolated from
    other Pods or processes on the same Node.
  policy: Unsafe sysctl options set
  resources:
  - apiVersion: apps/v1
    kind: ReplicaSet
    name: nginx-5fbc65fff
    namespace: test
    uid: 710f2142-7613-4cf5-aef7-dc65306626e2
  result: pass
  rule: KSV026
  severity: medium
  source: Trivy ConfigAudit
  timestamp:
    nanos: 0
    seconds: 1653395950
summary:
  error: 0
  fail: 26
  pass: 42
  skip: 0
  warn: 0
```
### CISKubeBenchReport

Maps CISKubeBenchReports into ClusterPolicyReports.

```yaml
apiVersion: wgpolicyk8s.io/v1alpha2
kind: ClusterPolicyReport
metadata:
  labels:
    managed-by: trivy-operator-polr-adapter
    trivy-operator.source: CISKubeBenchReport
  name: trivy-cis-cpolr-lima-rancher-desktop
  ownerReferences:
  - apiVersion: aquasecurity.github.io/v1alpha1
    kind: CISKubeBenchReport
    name: lima-rancher-desktop
    uid: 014fad85-58b6-4f94-bd49-1ee803a454fe
results:
- category: Worker Node Security Configuration
  message: |
    Run the below command (based on the file location on your system) on the each worker node.
    For example,
    chmod 644 /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
  policy: 4.1 Worker Node Configuration Files
  result: fail
  rule: 4.1.1 Ensure that the kubelet service file permissions are set to 644 or more
    restrictive (Automated)
  scored: true
  source: Trivy CIS Kube Bench
  timestamp:
    nanos: 0
    seconds: 1653506292
summary:
  error: 0
  fail: 11
  pass: 2
  skip: 0
  warn: 36
```

## Policy Reporter UI Screenshots

### VulnerabilityReports

![Policy Reporter UI - PolicyReport VulnerabilityReports Screenshot](https://github.com/fjogeleit/trivy-operator-polr-adapter/blob/main/screens/vulnr.png?raw=true)

### ConfigAuditReports

![Policy Reporter UI - PolicyReport ConfigAuditReports Screenshot](https://github.com/fjogeleit/trivy-operator-polr-adapter/blob/main/screens/config-audit.png?raw=true)

### CISKubeBenchReports

![Policy Reporter UI - PolicyReport CISKubeBenchReports Screenshot](https://github.com/fjogeleit/trivy-operator-polr-adapter/blob/main/screens/kube-bench.png?raw=true)

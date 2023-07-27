# 0.7.0

* Update dependencies
* Check OwnerReference values to avoid invalid OwnerReferences
* Use ClusterPolicyReport API to delete ClusterInfra Reports

# 0.6.0

* Add an API Server to provide a Healthz and Ready API
    * Both APIs checking for the existence of the PolicyReport CRDs
* Add PolicyReport CRDs to the Helm Chart, can be installed by setting `crds.install` to `true`

# 0.5.0

* New adapter for ClusterInfraAssessmentReport into ClusterPolicyReport mapping


# 0.4.2

* Map CVSS information as properties to PolicyReportResults of VulnerabilityReports

# 0.4.0

* Add TrivyOperator APIs to the project to reduce not needed dependencies
* Add PolicyReport CRD API and Client code to remove kyverno dependencies
* Support configure `CacheSyncTimeout` for the different clients
* Use `scope` instead of repeating the related `resource` in each result
    * If you use PolicyReporter, it requires AppVerion >= v2.13.0 to process the scope properly

# 0.3.2

* Fixed RBAC permssions for InfraAssementReport

# 0.3.1

* Add support for InfraAssementReport

# 0.3.0

* Add support for ClusterComplianceReport in `detailed` / `all` mode.

# 0.1.4

* Dependency Updates
* Remove duplicated `resources` in the deployment Helm File [[#33](https://github.com/fjogeleit/trivy-operator-polr-adapter/pull/33) by [caruccio](https://github.com/caruccio)]

# 0.1.1

* Check for duplicated IDs in ExposeSecret PolicyReports

# 0.1.0

* Add unique ResultID props to VulnerabilityReport results
* Remove duplicated results from ConfigAuditReport
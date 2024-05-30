package appshield.kubernetes.PSS002

import data.lib.kubernetes

default deny_missing_label = false

__rego_metadata__ := {
     "id": "PSS002",
     "title": "Mandatory Label Enforcement",
     "version": "v1.0.0",
     "severity": "High",
     "type": "K8sSecChk",
     "description": "This policy enforces mandatory labels on K8s resources to ensure they meet organizational labeling standards for security, compliance, and management.",
     "recommended_actions": "Review the Kubernetes resource definitions to ensure they include all mandatory labels: environment, app, component, confidentiality, owner, version, compliance, and cost-center. Update the resources to comply with the policy requirements."
}

__rego_input__ := {
  "combine": false,
  "selector": [
    {"type": "kubernetes", "group": "core", "version": "v1", "kind": "pod"},
    {"type": "kubernetes", "group": "apps", "version": "v1", "kind": "replicaset"},
    {"type": "kubernetes", "group": "core", "version": "v1", "kind": "replicationcontroller"},
    {"type": "kubernetes", "group": "apps", "version": "v1", "kind": "deployment"},
    {"type": "kubernetes", "group": "apps", "version": "v1", "kind": "statefulset"},
    {"type": "kubernetes", "group": "apps", "version": "v1", "kind": "daemonset"},
    {"type": "kubernetes", "group": "batch", "version": "v1", "kind": "cronjob"},
    {"type": "kubernetes", "group": "batch", "version": "v1", "kind": "job"},
    {"type": "kubernetes", "group": "core", "version": "v1", "kind": "namespace"}
  ]
}

mandatory_labels := [
    "environment",
    "app",
    "component",
    "confidentiality",
    "owner",
    "version",
    "compliance",
    "cost-center",
]

checkMandatoryLabels[label] {
  label := mandatory_labels[_]
  not input.review.object.metadata.labels[label]
}

deny_missing_label {
  count(checkMandatoryLabels) > 0
}

deny[res] {
  deny_missing_label
  resource_kind := lower(input.review.object.kind)
  missing_labels := concat(", ", checkMandatoryLabels)
  msg := sprintf(
      "%s %s in %s namespace is missing the following mandatory label(s): %s",
      [resource_kind, input.review.object.metadata.name, input.review.object.metadata.namespace, missing_labels]
  )
  res := {
    "msg": msg,
    "id": "PSS002",
    "title": "Mandatory Label Enforcement",
    "severity": "High",
    "type": "K8sSecChk",
    "description": "This policy enforces mandatory labels on K8s resources.",
    "recommended_actions": "Ensure your Kubernetes resource configurations include the mandatory labels."
  }
}

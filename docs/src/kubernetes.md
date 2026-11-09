# Kubernetes clusters

Credentials end up in clusters in places they should not be: literal `env` values in Deployments, ConfigMaps, and the `kubectl.kubernetes.io/last-applied-configuration` annotation, which repeats a Secret's data in plain text. `kubera scan k8s` reads a live cluster with read-only `list` calls.

```bash
kubera scan k8s                                   # current kubeconfig context, all namespaces
kubera scan k8s --context prod -n payments -n web # one context, two namespaces
kubera scan k8s --what configmaps,workloads       # skip Secrets
kubera scan k8s --verify --only-verified          # which stored credentials are live?
```

To scan manifests without cluster access, pipe them in instead. The [decoders](scanning.md#decoders) read the base64 `data:` of Secret manifests:

```bash
kubectl get secrets -A -o yaml | kubera scan stdin
```

## What gets scanned

| `--what` | Objects | Location in findings |
|---|---|---|
| `secrets` | Secret `data`, decoded. Service account tokens are skipped (the cluster mints them). | `secret/<namespace>/<name>` |
| `configmaps` | ConfigMap `data` and text in `binaryData` | `configmap/<namespace>/<name>` |
| `workloads` | Literal `env` values, `command` and `args` of Deployments, StatefulSets, DaemonSets, CronJobs, Jobs and standalone Pods | `deployment/<namespace>/<name>`, ... |

Annotations are scanned on every object, including `last-applied-configuration`. Pods and Jobs created by a controller are skipped, since they repeat their owner's template. Values loaded with `valueFrom` are references, not secrets, so they are not reported.

`scan k8s` finds secrets that are **supposed** to be in Secrets too. That is useful with `--verify` (which platforms' credentials does this cluster hold, and are they live?). Use `--what configmaps,workloads` to report only misplaced ones.

## Options

| Flag | Meaning |
|---|---|
| `--kubeconfig FILE` | Kubeconfig file (default: `$KUBECONFIG` or `~/.kube/config`). |
| `--context NAME` | Context to use (default: the current context). |
| `--in-cluster` | Use the service account of the pod kubera runs in. |
| `-n, --namespace NS` | Only these namespaces (repeatable, default: all). |
| `--what <kinds>` | `secrets`, `configmaps`, `workloads` (default: all). |

All [common scan options](scanning.md#common-options) work too.

## Access and TLS

Kubera reads the kubeconfig like kubectl: the context's cluster, CA, bearer token, client certificate, and `exec` credential plugins, so EKS, GKE and AKS logins work as they do for kubectl.

- TLS trusts **only the cluster's CA** when the kubeconfig names one.
- A cluster with `insecure-skip-tls-verify: true` is refused, and so is an `http://` server.
- Only `list` requests are sent. Nothing in the cluster is changed.
- When RBAC denies a kind (for example listing Secrets), the scan carries on and prints a warning for it.

## Running in the cluster

A nightly CronJob with a read-only ClusterRole, alerting a Slack channel when a live secret turns up (see [Alerts](alerts.md)):

```yaml
apiVersion: v1
kind: ServiceAccount
metadata: { name: kubera, namespace: security }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: kubera-read }
rules:
  - apiGroups: [""]
    resources: [secrets, configmaps, pods]
    verbs: [get, list]
  - apiGroups: [apps]
    resources: [deployments, statefulsets, daemonsets]
    verbs: [get, list]
  - apiGroups: [batch]
    resources: [jobs, cronjobs]
    verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: kubera-read }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: kubera-read }
subjects:
  - { kind: ServiceAccount, name: kubera, namespace: security }
---
apiVersion: batch/v1
kind: CronJob
metadata: { name: kubera, namespace: security }
spec:
  schedule: "17 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: kubera
          restartPolicy: Never
          containers:
            - name: kubera
              image: ghcr.io/dmdhrumilmistry/kubera:latest
              args: [scan, k8s, --in-cluster, --verify, --notify-env, SLACK_WEBHOOK]
              env:
                - name: SLACK_WEBHOOK
                  valueFrom:
                    secretKeyRef: { name: kubera-alerts, key: slack-webhook }
```

Create the webhook Secret first (`kubectl -n security create secret generic kubera-alerts --from-literal=slack-webhook=<webhook url>`). Pin the image to a release tag rather than `latest` in production.

- The scan reads the `kubera-alerts` Secret too, and would report the webhook in it. Skip it with `--exclude-path 'secret/<namespace>/kubera-alerts'` (paths are `<kind>/<namespace>/<name>`, so `--exclude-path 'secret/kube-system/**'` skips a whole namespace's Secrets).
- The ClusterRole can read every Secret in the cluster, so restrict who can use the `kubera` service account. Drop `secrets` from it (and pass `--what configmaps,workloads`) if you only want misplaced credentials.

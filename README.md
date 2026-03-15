# kubeportal
Kubeportal aims to be an end-to-end solution for secure, cross-cluster Kubernetes API connectivity.  
It allows workloads in a central cluster to seamlessly interact with the Kubernetes APIs of multiple remote clusters without exposing those clusters publicly.  
The kubeportal runs as a Deployment in Hub mode in the central cluster and as a Deployment in Agent mode in remote clusters.  
  
<img width="830" height="553" alt="diagram" src="https://github.com/user-attachments/assets/1c409c85-8c7a-40b8-a058-bc7861cd7992" />


## ⚠️ Status
kubeportal is an early prototype, still in active development.  
Expect breaking changes and incomplete features.  
It’s currently intended for exploration and internal testing rather than production use.

## How it Works
Agents establish outbound, TLS-secured connections to the Hub.  
These connections are used to proxy Kubernetes API requests initiated by workloads running in the Hub cluster.  
Authentication and authorization are enforced via native Kubernetes RBAC, using regular pod-mounted service account tokens that don't leave the cluster.

## Why kubeportal
- Seamless usage/integration for clients.
- No public API endpoints or shared credentials.
- Works entirely with Kubernetes-native primitives.
- Fine-grained, RBAC-based access controls on both sides.
- Simple Hub and Agent deployment model with horizontal scaling.

## Notes
- Streaming operations like exec are natively supported over websocket, which became the default starting from kubernetes 1.31, and can be [opted in](https://kubernetes.io/blog/2024/08/20/websockets-transition/)  from version 1.29.

## Related projects
- kube-oidc-proxy - also uses impersonation for cross-cluster auth but relies on remote API server to be network-accessible.
- Konnectivity - both kubeportal and Konnectivity use reverse connection initiation. Konnectivity is for API server -> node traffic while kubeportal is for pod-> remote API server traffic.
- Teleport - similar idea but primarily for human -> API server traffic instead of workload -> API server.

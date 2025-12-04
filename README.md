# kubeportal
Kubeportal aims to be an end-to-end solution for secure, cross-cluster Kubernetes API connectivity.  
It allows workloads in a central cluster to seamlessly interact with the Kubernetes APIs of multiple remote clusters without exposing those clusters publicly.  
The kubeportal runs as a Deployment in Hub mode in the central cluster and as a Deployment in Agent mode in remote clusters.  
  
![diagram](./diagram.png)

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

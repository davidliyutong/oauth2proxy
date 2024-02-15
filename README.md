
## Introduction

This toy project serves as an authentication proxy for applications that are not capable of handling authentication themselves. It is inspired by oauth2_proxy and is implemented in Python with Sanic. With the help of this proxy admins can add OIDC authentication to their applications without modifying the application code.

## Deployment

### Docker Based Deployment

Use `manifests/docker/docker-compose.yaml` to deploy the proxy using docker-compose.

```shell
cd manifests/docker
docker compose up -d
```

> You might need to change the OIDC settings according to your OIDC provider

> You might need a reverse proxy to serve the requests

### Kubernetes Deployment

Use `manifests/k8s/deployment.yaml` to deploy the proxy in a Kubernetes cluster.

```shell
kubectl apply -f manifests/k8s/deployment.yaml -n oauth2proxy
```

> You might need to change the OIDC settings according to your OIDC provider

> You might need to add appropriate certificate

## Ingress Annotations

Suppose your oauth2proxy deployment is at `https://oauth2proxy.example.com` and you want to protect your application at `https://app.example.com`. You can use the following annotations to protect your application with oauth2proxy.

```yaml
nginx.ingress.kubernetes.io/auth-url: https://oauth2proxy.example.com/v1/auth/oidc/validate
nginx.ingress.kubernetes.io/auth-signin: https://oauth2proxy.example.com/v1/auth/oidc/login
nginx.ingress.kubernetes.io/auth-cache-key: $cookie__oauth2proxy_auth_token
nginx.ingress.kubernetes.io/auth-always-set-cookie: true
```

## Application Configuration

The proxy will set the cookie `oauth2proxy_auth_token` after successful authentication. `oauth2proxy_auth_token` is a JWT token that encodes OIDC username. The application can use this cookie to authenticate the user. The application should also have a logout endpoint to clear the cookie.

Here is an example of the JWT token.

```json
{
  "username": "myj034988",
  "exp": 1707979918,
  "iat": 1707976318
}
```
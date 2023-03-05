# expose-oidc

This small tool enables the possiblity to expose an openid endpoint of a kubernets
cluster.
To enable oidc authentication from this cluster to aws services.

## Command line options
```
  --apiserver string
    	apiserver url (default "https://kubernetes.default.svc")
  --port int
    	port to listen on (default 80) [env: PORT]
  --publicUrl string
    	public url of the auth server (default "https://auth.mydomain.io")
  --serviceAccountPath string
    	base path of service account configuration (default "/var/run/secrets/kubernetes.io/serviceaccount")
```
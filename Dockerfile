FROM scratch

COPY expose-oidc /

ENTRYPOINT ["/expose-oidc"]

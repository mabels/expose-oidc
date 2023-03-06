FROM scratch

COPY ./expose-oidc /bin/expose-oidc

ENTRYPOINT ["expose-oidc"]

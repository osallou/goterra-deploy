# GoTorra deployment

manage recipe and app creations to deploy on multiple clouds (at first openstack but allows multiple sites).
Based on terraform

## Needs

mongodb, goterra-auth

## Environment variables

* GOT_ACL_USER_CREATENS: allow users to create namespaces (else only admin or super users can create one)

## Run

    GOT_CONFIG=goterra-deploy.yml GOT_PROXY_AUTH=http://localhost:8001 goterra-deploy 

## Special inputs

Some specific run input variables names are reserved:

* ssh_pub_key: if present, pub key will be added to authorized_keys

## Status

in development

## License

Apache 2.0

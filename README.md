# GoTorra deployment

manage recipe and app creations to deploy on multiple clouds (at first openstack but allows multiple sites).
Based on terraform

## Needs

mongodb, goterra-auth


## Run

    GOT_CONFIG=goterra-deploy.yml GOT_PROXY_AUTH=http://localhost:8001 goterra-deploy

## Status

in development

## License

Apache 2.0

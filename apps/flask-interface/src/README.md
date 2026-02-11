# Flask Ansible Interface

Flask application that executes Ansible playbooks on a remote EC2 control node via SSH.

## Features

- Web dashboard with JWT authentication
- REST API with API key authentication
- Remote Ansible playbook execution via SSH
- User management (password changes, API key generation)

## Environment Variables

See `apps/flask-interface/deployment.yaml` for all required environment variables.

## Build & Push

```bash
cd apps/flask-interface/src
docker build -t <your-registry>/flask-ansible:latest -f dockerfile .
docker push <your-registry>/flask-ansible:latest
```

## Deployment

Deployed via ArgoCD - see `apps/argocd-apps/flask-interface.yaml`

## Default Users

- **alice** / password1 (admin)
- **bob** / password2 (user)

**Change these in production!**

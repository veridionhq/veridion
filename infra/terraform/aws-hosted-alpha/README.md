# AWS Hosted Alpha

Recommended first hosted alpha:

- ECS Fargate for the API service
- ECS Fargate for the scheduler worker
- RDS Postgres for persistent control-plane state
- EFS for shared materialization output
- ALB for ingress
- S3 for event and analytics storage

Why this and not EKS or EC2:

- simpler than Kubernetes
- more production-like than a single EC2 host
- enough managed infrastructure to run a real alpha
- supports the split API + worker model cleanly

## Inputs

You need:

- an existing VPC
- public subnets for the ALB
- private subnets for ECS/RDS/EFS
- a built container image for Veridion
- JWT/JWKS settings for direct service auth

## Deploy

1. Build and push the image:

```bash
docker build -t veridion:alpha .
```

2. Fill in `terraform.tfvars`.

3. Apply:

```bash
terraform init
terraform apply
```

4. Run the migration task once after apply:

```bash
aws ecs run-task \
  --cluster "$(terraform output -raw ecs_cluster_name)" \
  --task-definition "$(terraform output -raw migrate_task_definition_arn)" \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[SUBNET_ID],securityGroups=[SECURITY_GROUP_ID],assignPublicIp=DISABLED}"
```

5. Create the first producer client through the admin API and start ingesting decision events.

## Opinionated path

Use this for the alpha:

- direct JWT/JWKS auth to the hosted API
- producer clients for CI ingestion
- no reverse proxy auth gateway yet
- no Kubernetes yet

Move to EKS only if:

- you already operate EKS well
- you need many internal services around Veridion
- you need cluster-level platform standardization more than simplicity

Move to EC2 only if:

- this is a temporary internal lab
- you explicitly want the absolute cheapest operational path

Otherwise, Fargate is the right middle ground.

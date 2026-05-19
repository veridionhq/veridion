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

- either:
  - let Terraform create the VPC/subnets/NAT path, or
  - supply an existing VPC plus public/private subnets
- a container image for Veridion
- JWT/JWKS settings for direct service auth

## Deploy

1. Fill in `terraform.tfvars`.

2. Apply the infrastructure with services scaled to zero first:

```bash
terraform init
terraform apply
```

3. Build and push the image to the created ECR repository:

```bash
export AWS_REGION=us-west-2
export ECR_REPOSITORY_URL="$(terraform output -raw ecr_repository_url)"
export IMAGE_TAG=alpha

./examples/aws/build-push-ecr.sh
```

4. Scale the ECS services up by setting:

- `service_desired_count = 1`
- `worker_desired_count = 1`

and run:

```bash
terraform apply
```

5. Run the migration task once after apply:

```bash
aws ecs run-task \
  --cluster "$(terraform output -raw ecs_cluster_name)" \
  --task-definition "$(terraform output -raw migrate_task_definition_arn)" \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=$(terraform output -json private_subnet_ids),securityGroups=[$(terraform output -raw ecs_security_group_id)],assignPublicIp=DISABLED}"
```

6. Create the first producer client through the admin API and start ingesting decision events.

## Opinionated path

Use this for the alpha:

- direct JWT/JWKS auth to the hosted API
- producer clients for CI ingestion
- no reverse proxy auth gateway yet
- no Kubernetes yet
- Terraform-created network by default
- ECS services scaled up only after the image exists

Move to EKS only if:

- you already operate EKS well
- you need many internal services around Veridion
- you need cluster-level platform standardization more than simplicity

Move to EC2 only if:

- this is a temporary internal lab
- you explicitly want the absolute cheapest operational path

Otherwise, Fargate is the right middle ground.

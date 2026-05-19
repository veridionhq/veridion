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

## Cheapest sane alpha

Use these defaults first:

- `create_nat_gateway = false`
- `ecs_tasks_in_public_subnets = true`
- `service_cpu = 256`
- `service_memory = 512`
- `worker_cpu = 256`
- `worker_memory = 512`
- `log_retention_in_days = 7`

Why:

- NAT Gateway is usually the biggest unnecessary fixed cost in this stack
- public-subnet Fargate tasks can still keep RDS private while avoiding NAT entirely
- the Veridion API and scheduler are light enough to start on the smallest Fargate shape here
- seven-day log retention is enough for an alpha without paying to keep two weeks by default

Move away from this cheaper mode only if:

- you need private-only task networking
- you need longer CloudWatch retention
- you see real CPU or memory pressure in the API or scheduler

## Inputs

You need:

- either:
  - let Terraform create the VPC/subnets path, or
  - supply an existing VPC plus public/private subnets
- a container image for Veridion
- JWT/JWKS settings for direct service auth
- optionally:
  - let Terraform create the GitHub Actions OIDC provider and ECR publish role, or
  - point Terraform at an existing GitHub OIDC provider ARN

## Deploy

1. Fill in `terraform.tfvars`.

Use normal HCL values there. Do not use `jsonencode(...)` inside the tfvars file.

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

bash ./examples/aws/build-push-ecr.sh
```

The hosted image is also built in CI on every push and pull request via `.github/workflows/hosted-image.yml`.
Use the workflow-dispatch path there when you want GitHub Actions to publish the image to ECR instead of pushing it manually from a shell.

For the CI publish path:

1. Apply Terraform.
2. Take the `github_actions_ecr_role_arn` output.
3. Set repository variable `AWS_GITHUB_ACTIONS_ROLE_ARN` to that value.
4. Ensure repository variable `ECR_REPOSITORY_URL` is set.
5. Run the `hosted-image` workflow with `push_to_ecr=true`.

If your AWS account already has the GitHub OIDC provider, set:

- `create_github_oidc_provider = false`
- `github_oidc_provider_arn = "<existing provider arn>"`

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
  --network-configuration "awsvpcConfiguration={subnets=$(terraform output -json ecs_task_subnet_ids),securityGroups=[$(terraform output -raw ecs_security_group_id)],assignPublicIp=$(terraform output -raw ecs_assign_public_ip)}"
```

6. Create the first producer client through the admin API and start ingesting decision events.

## Opinionated path

Use this for the alpha:

- direct JWT/JWKS auth to the hosted API
- producer clients for CI ingestion
- no reverse proxy auth gateway yet
- no Kubernetes yet
- Terraform-created network by default
- no NAT gateway by default
- public-subnet ECS tasks by default
- ECS services scaled up only after the image exists

Move to EKS only if:

- you already operate EKS well
- you need many internal services around Veridion
- you need cluster-level platform standardization more than simplicity

Move to EC2 only if:

- this is a temporary internal lab
- you explicitly want the absolute cheapest operational path

Otherwise, Fargate is the right middle ground.

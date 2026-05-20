data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  prefix               = var.name
  azs                  = length(var.availability_zones) > 0 ? var.availability_zones : slice(data.aws_availability_zones.available.names, 0, 2)
  chosen_vpc_id        = var.create_network ? aws_vpc.main[0].id : var.vpc_id
  public_subnet_ids    = var.create_network ? [for subnet in aws_subnet.public : subnet.id] : var.public_subnet_ids
  private_subnet_ids   = var.create_network ? [for subnet in aws_subnet.private : subnet.id] : var.private_subnet_ids
  ecs_task_subnet_ids  = var.ecs_tasks_in_public_subnets ? local.public_subnet_ids : local.private_subnet_ids
  ecs_assign_public_ip = var.ecs_tasks_in_public_subnets
  private_subnet_map = var.create_network ? {
    for key, subnet in aws_subnet.private : key => subnet.id
    } : {
    for idx, subnet_id in var.private_subnet_ids : tostring(idx) => subnet_id
  }
  ecr_repo_name          = var.ecr_repository_name != "" ? var.ecr_repository_name : local.prefix
  container_image        = var.container_image != "" ? var.container_image : "${aws_ecr_repository.app[0].repository_url}:${var.container_image_tag}"
  materialization_bucket = var.create_s3_bucket ? one(aws_s3_bucket.materializations[*].bucket) : var.s3_bucket_name
  db_host                = aws_db_instance.postgres.address
  db_port                = aws_db_instance.postgres.port
  store_dsn              = "postgresql://${var.db_username}:${var.db_password}@${local.db_host}:${local.db_port}/${var.db_name}"
  common_env = [
    { name = "VERIDION_SERVICE_NAME", value = "Veridion Hosted Control Plane" },
    { name = "VERIDION_STORE_DSN", value = local.store_dsn },
    { name = "VERIDION_MATERIALIZATION_ROOT", value = "/mnt/veridion-materialized" },
    { name = "VERIDION_JWT_ISSUER", value = var.jwt_issuer },
    { name = "VERIDION_JWT_AUDIENCE", value = var.jwt_audience },
    { name = "VERIDION_JWKS_URL", value = var.jwks_url },
    { name = "VERIDION_OIDC_DISCOVERY_URL", value = var.oidc_discovery_url },
    { name = "VERIDION_TENANTS_JSON", value = jsonencode(var.tenants) },
    { name = "VERIDION_SCHEDULES_JSON", value = jsonencode(var.schedules) },
    { name = "VERIDION_SERVICE_TOKENS_JSON", value = jsonencode(var.service_tokens) }
  ]
  github_oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github_actions[0].arn : var.github_oidc_provider_arn
  github_oidc_subjects = [
    for branch in var.github_allowed_branches : "repo:${var.github_repository}:ref:refs/heads/${branch}"
  ]
}

resource "aws_vpc" "main" {
  count                = var.create_network ? 1 : 0
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "${local.prefix}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  count  = var.create_network ? 1 : 0
  vpc_id = aws_vpc.main[0].id
}

resource "aws_subnet" "public" {
  for_each = var.create_network ? { for idx, cidr in var.public_subnet_cidrs : idx => cidr } : {}

  vpc_id                  = aws_vpc.main[0].id
  cidr_block              = each.value
  availability_zone       = local.azs[tonumber(each.key)]
  map_public_ip_on_launch = true

  tags = {
    Name = "${local.prefix}-public-${each.key}"
  }
}

resource "aws_subnet" "private" {
  for_each = var.create_network ? { for idx, cidr in var.private_subnet_cidrs : idx => cidr } : {}

  vpc_id            = aws_vpc.main[0].id
  cidr_block        = each.value
  availability_zone = local.azs[tonumber(each.key)]

  tags = {
    Name = "${local.prefix}-private-${each.key}"
  }
}

resource "aws_eip" "nat" {
  count  = var.create_network && var.create_nat_gateway ? 1 : 0
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  count         = var.create_network && var.create_nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = values(aws_subnet.public)[0].id

  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  count  = var.create_network ? 1 : 0
  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }
}

resource "aws_route_table_association" "public" {
  for_each       = var.create_network ? aws_subnet.public : {}
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  count  = var.create_network ? 1 : 0
  vpc_id = aws_vpc.main[0].id

  dynamic "route" {
    for_each = var.create_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.main[0].id
    }
  }
}

resource "aws_route_table_association" "private" {
  for_each       = var.create_network ? aws_subnet.private : {}
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[0].id
}

resource "aws_ecr_repository" "app" {
  count = var.create_ecr_repository ? 1 : 0
  name  = local.ecr_repo_name
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  count = var.create_github_actions_oidc_role && var.create_github_oidc_provider ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_cloudwatch_log_group" "service" {
  name              = "/ecs/${local.prefix}/service"
  retention_in_days = var.log_retention_in_days
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/${local.prefix}/worker"
  retention_in_days = var.log_retention_in_days
}

resource "aws_cloudwatch_log_group" "migrate" {
  name              = "/ecs/${local.prefix}/migrate"
  retention_in_days = var.log_retention_in_days
}

resource "aws_s3_bucket" "materializations" {
  count  = var.create_s3_bucket ? 1 : 0
  bucket = var.s3_bucket_name != "" ? var.s3_bucket_name : "${local.prefix}-materializations"
}

resource "aws_security_group" "alb" {
  name        = "${local.prefix}-alb"
  description = "ALB security group"
  vpc_id      = local.chosen_vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs" {
  name        = "${local.prefix}-ecs"
  description = "ECS task security group"
  vpc_id      = local.chosen_vpc_id

  ingress {
    from_port       = 8787
    to_port         = 8787
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "rds" {
  name        = "${local.prefix}-rds"
  description = "RDS security group"
  vpc_id      = local.chosen_vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }
}

resource "aws_security_group" "efs" {
  name        = "${local.prefix}-efs"
  description = "EFS security group"
  vpc_id      = local.chosen_vpc_id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }
}

resource "aws_lb" "service" {
  name               = replace(substr("${local.prefix}-alb", 0, 32), "_", "-")
  load_balancer_type = "application"
  subnets            = local.public_subnet_ids
  security_groups    = [aws_security_group.alb.id]
}

resource "aws_lb_target_group" "service" {
  name        = replace(substr("${local.prefix}-tg", 0, 32), "_", "-")
  port        = 8787
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = local.chosen_vpc_id

  health_check {
    path                = "/healthz"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.service.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service.arn
  }
}

resource "aws_db_subnet_group" "postgres" {
  name       = "${local.prefix}-db-subnets"
  subnet_ids = local.private_subnet_ids
}

resource "aws_db_instance" "postgres" {
  identifier             = "${local.prefix}-postgres"
  allocated_storage      = 20
  engine                 = "postgres"
  engine_version         = "16"
  instance_class         = "db.t4g.micro"
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.postgres.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  skip_final_snapshot    = true
  publicly_accessible    = false
}

resource "aws_efs_file_system" "materializations" {
  creation_token = "${local.prefix}-efs"
}

resource "aws_efs_mount_target" "materializations" {
  for_each        = local.private_subnet_map
  file_system_id  = aws_efs_file_system.materializations.id
  subnet_id       = each.value
  security_groups = [aws_security_group.efs.id]
}

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${local.prefix}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "task" {
  name               = "${local.prefix}-ecs-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

data "aws_iam_policy_document" "task" {
  statement {
    actions   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
    resources = var.create_s3_bucket ? [aws_s3_bucket.materializations[0].arn, "${aws_s3_bucket.materializations[0].arn}/*"] : ["arn:aws:s3:::${var.s3_bucket_name}", "arn:aws:s3:::${var.s3_bucket_name}/*"]
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "${local.prefix}-task"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

data "aws_iam_policy_document" "github_actions_assume" {
  count = var.create_github_actions_oidc_role ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.github_oidc_subjects
    }
  }
}

resource "aws_iam_role" "github_actions_ecr" {
  count = var.create_github_actions_oidc_role ? 1 : 0

  name               = "${local.prefix}-github-actions-ecr"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume[0].json
}

data "aws_iam_policy_document" "github_actions_ecr" {
  count = var.create_github_actions_oidc_role ? 1 : 0

  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
      "ecr:BatchGetImage"
    ]
    resources = [var.create_ecr_repository ? aws_ecr_repository.app[0].arn : "arn:aws:ecr:${var.aws_region}:*:repository/${local.ecr_repo_name}"]
  }
}

resource "aws_iam_role_policy" "github_actions_ecr" {
  count = var.create_github_actions_oidc_role ? 1 : 0

  name   = "${local.prefix}-github-actions-ecr"
  role   = aws_iam_role.github_actions_ecr[0].id
  policy = data.aws_iam_policy_document.github_actions_ecr[0].json
}

resource "aws_iam_role" "github_actions_deploy" {
  count = var.create_github_actions_deploy_role ? 1 : 0

  name               = "${local.prefix}-github-actions-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume[0].json
}

data "aws_iam_policy_document" "github_actions_deploy" {
  count = var.create_github_actions_deploy_role ? 1 : 0

  statement {
    actions = [
      "ecs:UpdateService",
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "ecs:RegisterTaskDefinition",
      "ecs:ListTasks",
      "ecs:DescribeTasks"
    ]
    resources = ["*"]
  }

  statement {
    actions = ["iam:PassRole"]
    resources = [
      aws_iam_role.execution.arn,
      aws_iam_role.task.arn
    ]
  }
}

resource "aws_iam_role_policy" "github_actions_deploy" {
  count = var.create_github_actions_deploy_role ? 1 : 0

  name   = "${local.prefix}-github-actions-deploy"
  role   = aws_iam_role.github_actions_deploy[0].id
  policy = data.aws_iam_policy_document.github_actions_deploy[0].json
}

resource "aws_ecs_cluster" "main" {
  name = "${local.prefix}-cluster"
}

resource "aws_ecs_task_definition" "service" {
  family                   = "${local.prefix}-service"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.service_cpu)
  memory                   = tostring(var.service_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  volume {
    name = "materializations"
    efs_volume_configuration {
      file_system_id = aws_efs_file_system.materializations.id
    }
  }

  container_definitions = jsonencode([
    {
      name      = "history-service"
      image     = local.container_image
      essential = true
      command   = ["/bin/bash", "examples/hosted/start-history-service.sh"]
      portMappings = [
        {
          containerPort = 8787
          hostPort      = 8787
          protocol      = "tcp"
        }
      ]
      mountPoints = [
        {
          sourceVolume  = "materializations"
          containerPath = "/mnt/veridion-materialized"
          readOnly      = false
        }
      ]
      environment = local.common_env
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${local.prefix}-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.worker_cpu)
  memory                   = tostring(var.worker_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  volume {
    name = "materializations"
    efs_volume_configuration {
      file_system_id = aws_efs_file_system.materializations.id
    }
  }

  container_definitions = jsonencode([
    {
      name      = "scheduler-worker"
      image     = local.container_image
      essential = true
      command   = ["/bin/bash", "examples/hosted/start-history-scheduler.sh"]
      mountPoints = [
        {
          sourceVolume  = "materializations"
          containerPath = "/mnt/veridion-materialized"
          readOnly      = false
        }
      ]
      environment = local.common_env
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.worker.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_task_definition" "migrate" {
  family                   = "${local.prefix}-migrate"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "migrate"
      image     = local.container_image
      essential = true
      command   = ["/bin/bash", "examples/hosted/start-history-migrate.sh"]
      environment = [
        { name = "VERIDION_STORE_DSN", value = local.store_dsn }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.migrate.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "service" {
  name            = "${local.prefix}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.service.arn
  desired_count   = var.service_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = local.ecs_task_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = local.ecs_assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.service.arn
    container_name   = "history-service"
    container_port   = 8787
  }

  depends_on = [aws_lb_listener.http]
}

resource "aws_ecs_service" "worker" {
  name            = "${local.prefix}-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = local.ecs_task_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = local.ecs_assign_public_ip
  }
}

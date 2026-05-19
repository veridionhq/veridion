#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:?set AWS_REGION}"
: "${ECR_REPOSITORY_URL:?set ECR_REPOSITORY_URL}"

IMAGE_TAG="${IMAGE_TAG:-alpha}"
IMAGE_URI="${ECR_REPOSITORY_URL}:${IMAGE_TAG}"

aws ecr get-login-password --region "${AWS_REGION}" \
  | docker login --username AWS --password-stdin "${ECR_REPOSITORY_URL%/*}"

docker build -t "${IMAGE_URI}" .
docker push "${IMAGE_URI}"

echo "Pushed ${IMAGE_URI}"

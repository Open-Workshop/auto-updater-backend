#!/usr/bin/env bash
set -euo pipefail

# Deployment script for auto-updater-backend changes
# Run this on the production server: 212.22.82.180

echo "==> Starting deployment..."

# Check if we're in the right directory
if [[ ! -f "main.py" ]]; then
    echo "Error: Please run this script from the auto-updater-backend directory"
    exit 1
fi

# Pull latest changes
echo "==> Pulling latest changes from git..."
git pull origin main || git pull origin $(git branch --show-current)

# Create tag for this deployment
TAG="cpu-fix-$(date +%Y%m%d-%H%M%S)"
echo "==> Using tag: $TAG"

# Build the image
echo "==> Building Docker image..."
buildah bud -t "localhost/auto-updater-backend:${TAG}" .

# Tag for registry
echo "==> Tagging image..."
buildah tag "localhost/auto-updater-backend:${TAG}" "docker.io/library/auto-updater-backend:${TAG}"

# Create archive
ARCHIVE_PATH="/tmp/auto-updater-${TAG}.tar"
echo "==> Creating Docker archive: ${ARCHIVE_PATH}"
rm -f "${ARCHIVE_PATH}"
buildah push "docker.io/library/auto-updater-backend:${TAG}" "docker-archive:${ARCHIVE_PATH}:docker.io/library/auto-updater-backend:${TAG}"

# Import into k3s
echo "==> Importing image into k3s/containerd..."
ctr -n k8s.io images import "${ARCHIVE_PATH}"

# Find values file
VALUES_FILE=""
if [[ -f "/root/auto-updater-values.yaml" ]]; then
    VALUES_FILE="/root/auto-updater-values.yaml"
elif [[ -f "./auto-updater-values.yaml" ]]; then
    VALUES_FILE="./auto-updater-values.yaml"
else
    echo "Error: Could not find values file"
    exit 1
fi

echo "==> Using values file: ${VALUES_FILE}"

# Update image tag in values file
echo "==> Updating image tag in values file..."
python3 - "${VALUES_FILE}" "${TAG}" <<'PY'
import pathlib
import re
import sys

values_path = pathlib.Path(sys.argv[1])
tag = sys.argv[2]
text = values_path.read_text()
updated, count = re.subn(r"(?m)^(\s*tag:\s*).*$", rf"\1{tag}", text, count=1)
if count != 1:
    raise SystemExit("could not find image.tag line in values file")
values_path.write_text(updated)
PY

# Helm upgrade
echo "==> Applying MirrorInstance CRD..."
k3s kubectl apply -f charts/auto-updater/crds/mirrorinstances.yaml

echo "==> Running Helm upgrade..."
helm upgrade auto-updater charts/auto-updater -n auto-updater -f "${VALUES_FILE}"

# Wait for rollouts
echo "==> Waiting for operator rollout..."
k3s kubectl -n auto-updater rollout status deployment/auto-updater-operator --timeout=240s

echo "==> Waiting for UI rollout..."
k3s kubectl -n auto-updater rollout status deployment/auto-updater-ui --timeout=240s

echo "==> Waiting for managed StatefulSet rollouts..."
mapfile -t MANAGED_STATEFULSETS < <(
    k3s kubectl -n auto-updater get statefulset \
        -l app.kubernetes.io/part-of=auto-updater \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
)
for statefulset in "${MANAGED_STATEFULSETS[@]}"; do
    [[ -n "$statefulset" ]] || continue
    replicas="$(k3s kubectl -n auto-updater get "statefulset/${statefulset}" -o jsonpath='{.spec.replicas}')"
    if [[ "${replicas:-0}" == "0" ]]; then
        echo "==> Skipping statefulset/${statefulset} rollout wait (replicas=0)"
        continue
    fi
    k3s kubectl -n auto-updater rollout status "statefulset/${statefulset}" --timeout=240s
done

echo "==> Migrating MirrorInstance resources to canonical schema..."
python3 scripts/migrate_mirrorinstances.py \
    --namespace auto-updater \
    --kube-cli "k3s kubectl"

echo "==> Deployment completed successfully!"
echo "==> Current workload status:"
k3s kubectl -n auto-updater get deploy,sts,pod -o wide

echo ""
echo "==> Changes deployed:"
echo "    - Timestamps in logs now show without milliseconds"
echo "    - CPU usage now displays as percentage instead of millicores"

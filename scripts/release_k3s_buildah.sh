#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RELEASE_NAME="${RELEASE_NAME:-auto-updater}"
NAMESPACE="${NAMESPACE:-auto-updater}"
CHART_PATH="${CHART_PATH:-$ROOT_DIR/charts/auto-updater}"
VALUES_FILE="${VALUES_FILE:-}"
IMAGE_NAME="${IMAGE_NAME:-auto-updater-backend}"
IMAGE_REGISTRY="${IMAGE_REGISTRY:-docker.io/library}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-/etc/rancher/k3s/k3s.yaml}"
KUBE_CLI="${KUBE_CLI:-kubectl}"
TAG="${TAG:-}"
ARCHIVE_PATH="${ARCHIVE_PATH:-}"
USE_LAYERS=1
SKIP_IMPORT=0
SKIP_DEPLOY=0

usage() {
  cat <<EOF
Usage: $(basename "$0") --tag <image-tag> --values <values.yaml> [options]

Options:
  --tag <tag>             Image tag to build and deploy.
  --values <path>         Helm values file to update with the new image tag.
  --release <name>        Helm release name. Default: ${RELEASE_NAME}
  --namespace <ns>        Kubernetes namespace. Default: ${NAMESPACE}
  --chart <path>          Helm chart path. Default: ${CHART_PATH}
  --archive <path>        Docker archive output path.
  --image-name <name>     Image name without registry. Default: ${IMAGE_NAME}
  --image-registry <ref>  Image registry/repository prefix. Default: ${IMAGE_REGISTRY}
  --kubeconfig <path>     KUBECONFIG path. Default: ${KUBECONFIG_PATH}
  --kube-cli <command>    kubectl command. Default: ${KUBE_CLI}
  --skip-import           Skip ctr image import.
  --skip-deploy           Skip helm upgrade and rollout checks.
  --no-layers             Disable buildah layer cache. Layers are enabled by default.
  -h, --help              Show this help.

Examples:
  $(basename "$0") --tag prod-20260326-9 --values /root/auto-updater-values.yaml --kube-cli "k3s kubectl"
  $(basename "$0") --tag cache-smoke --values /root/auto-updater-values.yaml --skip-deploy --skip-import
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --values)
      VALUES_FILE="${2:-}"
      shift 2
      ;;
    --release)
      RELEASE_NAME="${2:-}"
      shift 2
      ;;
    --namespace)
      NAMESPACE="${2:-}"
      shift 2
      ;;
    --chart)
      CHART_PATH="${2:-}"
      shift 2
      ;;
    --archive)
      ARCHIVE_PATH="${2:-}"
      shift 2
      ;;
    --image-name)
      IMAGE_NAME="${2:-}"
      shift 2
      ;;
    --image-registry)
      IMAGE_REGISTRY="${2:-}"
      shift 2
      ;;
    --kubeconfig)
      KUBECONFIG_PATH="${2:-}"
      shift 2
      ;;
    --kube-cli)
      KUBE_CLI="${2:-}"
      shift 2
      ;;
    --skip-import)
      SKIP_IMPORT=1
      shift
      ;;
    --skip-deploy)
      SKIP_DEPLOY=1
      shift
      ;;
    --no-layers)
      USE_LAYERS=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$TAG" ]] || fail "--tag is required"
if [[ $SKIP_DEPLOY -eq 0 ]]; then
  [[ -n "$VALUES_FILE" ]] || fail "--values is required unless --skip-deploy is used"
fi

ARCHIVE_PATH="${ARCHIVE_PATH:-$ROOT_DIR/${IMAGE_NAME}-${TAG}.tar}"
LOCAL_IMAGE_REF="localhost/${IMAGE_NAME}:${TAG}"
REMOTE_IMAGE_REF="${IMAGE_REGISTRY}/${IMAGE_NAME}:${TAG}"
read -r -a KUBE_CLI_ARR <<<"$KUBE_CLI"

require_cmd python3
require_cmd buildah
if [[ $SKIP_IMPORT -eq 0 ]]; then
  require_cmd ctr
fi
if [[ $SKIP_DEPLOY -eq 0 ]]; then
  require_cmd helm
  require_cmd "${KUBE_CLI_ARR[0]}"
  [[ -f "$VALUES_FILE" ]] || fail "values file not found: $VALUES_FILE"
  [[ -f "$KUBECONFIG_PATH" ]] || fail "kubeconfig not found: $KUBECONFIG_PATH"
fi
[[ -d "$CHART_PATH" ]] || fail "chart path not found: $CHART_PATH"

echo "==> Syntax check"
python3 -m py_compile "$ROOT_DIR"/*.py

echo "==> Building image ${LOCAL_IMAGE_REF}"
BUILD_CMD=(buildah bud)
if [[ $USE_LAYERS -eq 1 ]]; then
  BUILD_CMD+=(--layers)
fi
BUILD_CMD+=(-t "$LOCAL_IMAGE_REF" "$ROOT_DIR")
"${BUILD_CMD[@]}"

echo "==> Tagging image as ${REMOTE_IMAGE_REF}"
buildah tag "$LOCAL_IMAGE_REF" "$REMOTE_IMAGE_REF"

if [[ $SKIP_IMPORT -eq 0 ]]; then
  echo "==> Writing docker archive ${ARCHIVE_PATH}"
  rm -f "$ARCHIVE_PATH"
  buildah push "$REMOTE_IMAGE_REF" "docker-archive:${ARCHIVE_PATH}:${REMOTE_IMAGE_REF}"

  echo "==> Importing image into k3s/containerd"
  ctr -n k8s.io images import "$ARCHIVE_PATH"
fi

if [[ $SKIP_DEPLOY -eq 1 ]]; then
  echo "==> Build finished (deploy skipped)"
  exit 0
fi

echo "==> Updating image tag in ${VALUES_FILE}"
python3 - "$VALUES_FILE" "$TAG" <<'PY'
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

echo "==> Helm upgrade ${RELEASE_NAME}"
export KUBECONFIG="$KUBECONFIG_PATH"
helm upgrade "$RELEASE_NAME" "$CHART_PATH" -n "$NAMESPACE" -f "$VALUES_FILE"

echo "==> Waiting for operator and UI rollouts"
"${KUBE_CLI_ARR[@]}" -n "$NAMESPACE" rollout status "deployment/${RELEASE_NAME}-operator" --timeout=240s
"${KUBE_CLI_ARR[@]}" -n "$NAMESPACE" rollout status "deployment/${RELEASE_NAME}-ui" --timeout=240s

echo "==> Current workload status"
"${KUBE_CLI_ARR[@]}" -n "$NAMESPACE" get deploy,sts,pod -o wide

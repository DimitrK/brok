#!/usr/bin/env bash
# Infrastructure teardown script for broker-interceptor
# Usage: ./scripts/infra-down.sh [--volumes]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Default values
REMOVE_VOLUMES=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --volumes)
      REMOVE_VOLUMES=true
      shift
      ;;
    --help)
      echo "Usage: $0 [--volumes]"
      echo ""
      echo "Options:"
      echo "  --volumes    Remove data volumes (destructive - deletes all data)"
      echo "  --help       Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

cd "$ROOT_DIR"

echo "Stopping broker-interceptor infrastructure..."

PROFILE_FLAGS=(--profile apps --profile tools --profile vault)

if [ "$REMOVE_VOLUMES" = true ]; then
  echo "Warning: Removing all data volumes..."
  docker compose "${PROFILE_FLAGS[@]}" down -v --remove-orphans
  echo "Infrastructure stopped and volumes removed."
else
  docker compose "${PROFILE_FLAGS[@]}" down --remove-orphans
  echo "Infrastructure stopped. Data volumes preserved."
  echo "Use --volumes flag to remove data volumes."
fi

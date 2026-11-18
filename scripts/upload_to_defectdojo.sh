#!/usr/bin/env bash
# Upload sec. scan report to DefectDojo (/api/v2/reimport-scan/)
# Works in GitHub Actions (via secrets) and locally for demos
# Usage:
#   bash scripts/upload_to_defectdojo.sh "<scan_type>" "<report_file>" "<test_title>"

set -euo pipefail

SCAN_TYPE="${1:?Usage: upload_to_defectdojo.sh <scan_type> <report_file> <test_title>}"
REPORT_FILE="${2:?Missing report file path}"
TEST_TITLE="${3:?Missing test title}"

if [ -z "${DEFECTDOJO_URL:-}" ] || [ -z "${DEFECTDOJO_API_KEY:-}" ]; then
  echo "DefectDojo credentials are not configured (DEFECTDOJO_URL / DEFECTDOJO_API_KEY). Skipping upload for '${TEST_TITLE}'."
  exit 0
fi

case "${DEFECTDOJO_URL}" in
  http://*|https://*) ;;
  *)
    echo "::error::DEFECTDOJO_URL must start with http:// or https://"
    exit 1
    ;;
esac

if [ ! -s "${REPORT_FILE}" ]; then
  echo "Report file '${REPORT_FILE}' not found or empty. Skipping upload for '${TEST_TITLE}'."
  exit 0
fi

PRODUCT_NAME="${DEFECTDOJO_PRODUCT_NAME:-Secure-BioVault}"
PRODUCT_TYPE_NAME="${DEFECTDOJO_PRODUCT_TYPE:-Healthcare Platform}"
ENGAGEMENT_NAME="${DEFECTDOJO_ENGAGEMENT_NAME:-CI/CD Security Scans}"
BRANCH_NAME="${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'local')}"
COMMIT_SHA="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo 'local')}"
ENDPOINT="${DEFECTDOJO_URL%/}/api/v2/reimport-scan/"

echo "Uploading '${REPORT_FILE}' (${SCAN_TYPE} -> '${TEST_TITLE}') to DefectDojo..."

HTTP_CODE=$(curl -sS -o /tmp/dd_response.json -w "%{http_code}" \
  -X POST "${ENDPOINT}" \
  -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
  -F "scan_type=${SCAN_TYPE}" \
  -F "file=@${REPORT_FILE}" \
  -F "product_name=${PRODUCT_NAME}" \
  -F "product_type_name=${PRODUCT_TYPE_NAME}" \
  -F "engagement_name=${ENGAGEMENT_NAME}" \
  -F "test_title=${TEST_TITLE}" \
  -F "auto_create_context=true" \
  -F "active=true" \
  -F "verified=false" \
  -F "close_old_findings=true" \
  -F "deduplication_on_engagement=true" \
  -F "branch_tag=${BRANCH_NAME}" \
  -F "commit_hash=${COMMIT_SHA}")

if [ "${HTTP_CODE}" -lt 200 ] || [ "${HTTP_CODE}" -ge 300 ]; then
  echo "::warning::DefectDojo upload failed for '${TEST_TITLE}' (HTTP ${HTTP_CODE}):"
  cat /tmp/dd_response.json
  echo ""
  exit 1
fi

echo "DefectDojo upload succeeded for '${TEST_TITLE}' (HTTP ${HTTP_CODE})."

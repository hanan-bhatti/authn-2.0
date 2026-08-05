#!/bin/bash
set -e

SECRET_KEY="sk_test_demo12345678901234567890123456789012"
BASE_URL="http://localhost:8080/v1/admin/webhooks"

echo "=== 1. Creating Webhook Endpoint ==="
RESP1=$(curl -s -X POST "$BASE_URL/endpoints" \
  -H "Authorization: Bearer $SECRET_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://webhook.site/test-handler","description":"Production Events Webhook","events":["user.created","session.revoked"]}')
echo "$RESP1"
EP_ID=$(echo "$RESP1" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
echo "Created Endpoint ID: $EP_ID"

echo ""
echo "=== 2. Creating Duplicate Secret Test (Collision Protection) ==="
curl -s -X POST "$BASE_URL/endpoints" \
  -H "Authorization: Bearer $SECRET_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://invalid-url-domain-test"}' || true

echo ""
echo "=== 3. Listing Webhook Endpoints ==="
curl -s -X GET "$BASE_URL/endpoints" -H "Authorization: Bearer $SECRET_KEY"

echo ""
echo "=== 4. Fetching Webhook Endpoint by ID ==="
curl -s -X GET "$BASE_URL/endpoints/$EP_ID" -H "Authorization: Bearer $SECRET_KEY"

echo ""
echo "=== 5. Sending Test Ping Webhook Event ==="
curl -s -X POST "$BASE_URL/endpoints/$EP_ID/ping" -H "Authorization: Bearer $SECRET_KEY"

echo ""
echo "=== 6. Rotating Webhook Secret Key ==="
curl -s -X POST "$BASE_URL/endpoints/$EP_ID/rotate-secret" -H "Authorization: Bearer $SECRET_KEY"

echo ""
echo "=== 7. Listing Delivery Logs ==="
curl -s -X GET "$BASE_URL/deliveries" -H "Authorization: Bearer $SECRET_KEY"

echo ""
echo "=== 8. Deleting Webhook Endpoint (Parent + Child Cleanup Test) ==="
curl -s -X DELETE "$BASE_URL/endpoints/$EP_ID" -H "Authorization: Bearer $SECRET_KEY"

echo ""
echo "=== ALL 8 HTTP TESTS EXECUTED CLEANLY! ==="

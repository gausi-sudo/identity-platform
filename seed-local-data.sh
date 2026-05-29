#!/usr/bin/env bash
# Seed sample organizations and users on a running local instance, and
# write the local niro/credentials.yaml that security testing uses to
# authenticate. Safe to re-run (existing rows are left in place).
#
# Usage: ./seed-local-data.sh [base-url]    (default: http://localhost:8000)

set -euo pipefail

BASE_URL="${1:-http://localhost:8000}"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

ADMIN_USER="admin"
ADMIN_ORG="built-in"
ADMIN_APP="app-built-in"
ADMIN_PASS="123"

USER_ORG="test-org"
USER_APP="app-test-org"
USER_A="alice"
USER_A_PASS="Alice-2026-Ax"
USER_B="bob"
USER_B_PASS="Bob-2026-Bx"

die() { echo "ERROR: $*" >&2; exit 1; }

# --- Admin login ---
status=$(curl -sf -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/api/login" \
  -H "Content-Type: application/json" \
  -d "{\"application\":\"$ADMIN_APP\",\"organization\":\"$ADMIN_ORG\",\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\",\"type\":\"login\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
[ "$status" = "ok" ] || die "Admin login failed (is the server running at $BASE_URL?)"

# --- Ensure org exists ---
curl -sf -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/api/add-organization" \
  -H "Content-Type: application/json" \
  -d "{\"owner\":\"admin\",\"name\":\"$USER_ORG\",\"displayName\":\"Test Org\",\"passwordType\":\"plain\",\"passwordOptions\":[\"AtLeast6\"],\"countryCodes\":[\"US\"]}" \
  > /dev/null 2>&1 || true  # ignore duplicate error

# --- Ensure app exists ---
curl -sf -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/api/add-application" \
  -H "Content-Type: application/json" \
  -d "{\"owner\":\"admin\",\"name\":\"$USER_APP\",\"displayName\":\"Test App\",\"organization\":\"$USER_ORG\",\"enablePassword\":true,\"enableSignUp\":true,\"providers\":[]}" \
  > /dev/null 2>&1 || true

create_and_reset_user() {
  local org="$1" user="$2" pass="$3" app="$4" phone="$5"
  local status

  curl -sf -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/add-user" \
    -H "Content-Type: application/json" \
    -d "{\"owner\":\"$org\",\"name\":\"$user\",\"password\":\"$pass\",\"displayName\":\"$user\",\"email\":\"$user@$org.local\",\"phone\":\"$phone\",\"countryCode\":\"US\",\"isAdmin\":false,\"signupApplication\":\"$app\"}" \
    > /dev/null 2>&1 || true

  status=$(curl -sf \
    -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"application\":\"$app\",\"organization\":\"$org\",\"username\":\"$user\",\"password\":\"$pass\",\"type\":\"login\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")

  if [ "$status" != "ok" ]; then
    local set_msg set_status
    set_msg=$(curl -sf -b "$COOKIE_JAR" \
      -X POST "$BASE_URL/api/set-password" \
      -d "userOwner=$org&userName=$user&newPassword=$pass" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''),d.get('msg',''))")
    set_status="${set_msg%% *}"

    if [ "$set_status" != "ok" ]; then
      local tmp_pass="${pass}_tmp"
      curl -sf -b "$COOKIE_JAR" \
        -X POST "$BASE_URL/api/set-password" \
        -d "userOwner=$org&userName=$user&newPassword=$tmp_pass" \
        > /dev/null 2>&1 || true
      status=$(curl -sf -b "$COOKIE_JAR" \
        -X POST "$BASE_URL/api/set-password" \
        -d "userOwner=$org&userName=$user&newPassword=$pass" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
      [ "$status" = "ok" ] || die "set-password failed for $org/$user after temp-bounce"
    fi
  fi

  status=$(curl -sf \
    -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"application\":\"$app\",\"organization\":\"$org\",\"username\":\"$user\",\"password\":\"$pass\",\"type\":\"login\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
  [ "$status" = "ok" ] || die "login verification failed for $org/$user"
}

create_and_reset_user "$USER_ORG" "$USER_A" "$USER_A_PASS" "$USER_APP" "10000000001"
create_and_reset_user "$USER_ORG" "$USER_B" "$USER_B_PASS" "$USER_APP" "10000000002"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CREDS_FILE="$SCRIPT_DIR/niro/credentials.yaml"

python3 - <<EOF
admin_login  = "POST /api/login with JSON body {application:'$ADMIN_APP', organization:'$ADMIN_ORG', username:'$ADMIN_USER', password:'$ADMIN_PASS', type:'login'}"
user_login_a = "POST /api/login with JSON body {application:'$USER_APP', organization:'$USER_ORG', username:'$USER_A', password:'$USER_A_PASS', type:'login'}"
user_login_b = "POST /api/login with JSON body {application:'$USER_APP', organization:'$USER_ORG', username:'$USER_B', password:'$USER_B_PASS', type:'login'}"

yaml = f"""credentials:
  - description: >-
      Global admin for the $ADMIN_ORG organization. {admin_login}.
      Full access to all admin endpoints (user management, key management,
      org-level resources). Pair with standard users to verify lower-role
      accounts are denied at admin surfaces.
    type: username_password
    identifier: "$ADMIN_USER"
    secret: "$ADMIN_PASS"

  - description: >-
      Standard user A in $USER_ORG. {user_login_a}.
      Owns resources in $USER_ORG. Pair with $USER_B: authenticate as A,
      attempt to read/modify B's resources, expect denial. Must not reach
      admin or $ADMIN_ORG endpoints.
    type: username_password
    identifier: "$USER_A"
    secret: "$USER_A_PASS"

  - description: >-
      Standard user B in $USER_ORG. {user_login_b}.
      Different resources from $USER_A so cross-account access attempts
      have something to fail at. Pair with $USER_A.
    type: username_password
    identifier: "$USER_B"
    secret: "$USER_B_PASS"
"""

with open("$CREDS_FILE", "w") as f:
    f.write(yaml)
print("wrote", "$CREDS_FILE")
EOF

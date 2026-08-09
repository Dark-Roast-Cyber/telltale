#!/usr/bin/env bash
# Live end-to-end test for Telltale event sinks against local Docker services.
#
# Nothing here is hardcoded to a deployment: endpoints, ports, and credentials
# are discovered at runtime from the running containers (`docker port`,
# container env), exported as process-local environment variables, and written
# only into the gitignored local/ directory. Safe to run repeatedly.
#
# Requirements:
#   - docker CLI access to the containers below
#   - an Elasticsearch container (default: docker-elk-elasticsearch-1)
#   - optionally a Splunk container (default: splunk) — skipped if absent
#
# Overrides:
#   ADR_LIVETEST_ES_CONTAINER      Elasticsearch container name
#   ADR_LIVETEST_SPLUNK_CONTAINER  Splunk container name
#   ADR_LIVETEST_ES_INDEX          target ES index (default telltale-events-livetest)
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
LOCAL_DIR="$REPO_ROOT/local"
OUT_DIR="$LOCAL_DIR/outputs.d"
LOG_PATH="$LOCAL_DIR/live-events.jsonl"
STATE_PATH="$LOCAL_DIR/live-state.json"
ES_CONTAINER="${ADR_LIVETEST_ES_CONTAINER:-docker-elk-elasticsearch-1}"
SPLUNK_CONTAINER="${ADR_LIVETEST_SPLUNK_CONTAINER:-splunk}"
ES_INDEX="${ADR_LIVETEST_ES_INDEX:-telltale-events-livetest}"
HEC_TOKEN_NAME="telltale-livetest"

note() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

container_env() { # container_env <container> <VAR>
    docker inspect "$1" --format '{{range .Config.Env}}{{println .}}{{end}}' \
        | awk -F= -v k="$2" '$1 == k { sub($1 FS, ""); print; exit }'
}

host_port() { # host_port <container> <port/proto> -> 127.0.0.1:<mapped>
    local mapped
    mapped=$(docker port "$1" "$2" 2>/dev/null | head -1) || return 1
    [ -n "$mapped" ] || return 1
    printf '127.0.0.1:%s' "${mapped##*:}"
}

# ---------------------------------------------------------------- Elasticsearch
note "Discovering Elasticsearch ($ES_CONTAINER)"
docker inspect "$ES_CONTAINER" >/dev/null 2>&1 || fail "container $ES_CONTAINER not found"
if [ "$(docker inspect "$ES_CONTAINER" --format '{{.State.Running}}')" != "true" ]; then
    docker start "$ES_CONTAINER" >/dev/null
fi
ES_ADDR=$(host_port "$ES_CONTAINER" 9200/tcp) || fail "no published 9200 port on $ES_CONTAINER"
ADR_LIVETEST_ES_PASSWORD=$(container_env "$ES_CONTAINER" ELASTIC_PASSWORD)
[ -n "$ADR_LIVETEST_ES_PASSWORD" ] || fail "ELASTIC_PASSWORD not present in $ES_CONTAINER env"
export ADR_LIVETEST_ES_PASSWORD

ES_SCHEME=http
if ! curl -s -m 5 -o /dev/null "http://$ES_ADDR"; then
    ES_SCHEME=https
fi
ES_URL="$ES_SCHEME://$ES_ADDR"
es_curl() { curl -s -m 15 -u "elastic:$ADR_LIVETEST_ES_PASSWORD" ${ES_SCHEME:+$([ "$ES_SCHEME" = https ] && echo -k)} "$@"; }

for _ in $(seq 1 30); do
    if es_curl -o /dev/null -w '' "$ES_URL" 2>/dev/null; then break; fi
    sleep 2
done
es_curl "$ES_URL" | grep -q cluster_name || fail "Elasticsearch at $ES_URL not reachable with derived credentials"
echo "Elasticsearch ready at $ES_URL"

# Start each run from a clean test index so counts are exact.
es_curl -X DELETE "$ES_URL/$ES_INDEX" >/dev/null || true

# ---------------------------------------------------------------------- Splunk
SPLUNK_AVAILABLE=false
ADR_LIVETEST_HEC_TOKEN=""
if docker inspect "$SPLUNK_CONTAINER" >/dev/null 2>&1; then
    note "Discovering Splunk ($SPLUNK_CONTAINER)"
    if [ "$(docker inspect "$SPLUNK_CONTAINER" --format '{{.State.Running}}')" != "true" ]; then
        docker start "$SPLUNK_CONTAINER" >/dev/null
    fi
    echo "Waiting for Splunk health (up to 300s)..."
    for _ in $(seq 1 100); do
        health=$(docker inspect "$SPLUNK_CONTAINER" --format '{{.State.Health.Status}}' 2>/dev/null || echo none)
        [ "$health" = healthy ] && break
        sleep 3
    done
    if [ "$health" = healthy ]; then
        SPLUNK_PASSWORD=$(container_env "$SPLUNK_CONTAINER" SPLUNK_PASSWORD)
        MGMT_ADDR=$(host_port "$SPLUNK_CONTAINER" 8089/tcp) || true
        HEC_ADDR=$(host_port "$SPLUNK_CONTAINER" 8088/tcp) || true
        if [ -n "$SPLUNK_PASSWORD" ] && [ -n "${MGMT_ADDR:-}" ] && [ -n "${HEC_ADDR:-}" ]; then
            mgmt() { curl -sk -m 20 -u "admin:$SPLUNK_PASSWORD" "$@"; }
            # Ensure the telltale index exists (the sink's default HEC index).
            if ! mgmt "https://$MGMT_ADDR/services/data/indexes/telltale?output_mode=json" -o /dev/null -w '%{http_code}' | grep -q 200; then
                mgmt -X POST "https://$MGMT_ADDR/services/data/indexes" -d name=telltale >/dev/null \
                    && echo "Created Splunk index 'telltale'"
            fi
            # Ensure HEC is enabled and a named test token exists.
            mgmt -X POST "https://$MGMT_ADDR/services/data/inputs/http/http" -d disabled=0 >/dev/null || true
            token_json=$(mgmt "https://$MGMT_ADDR/services/data/inputs/http/$HEC_TOKEN_NAME?output_mode=json" || true)
            if ! printf '%s' "$token_json" | grep -q '"token"'; then
                token_json=$(mgmt -X POST "https://$MGMT_ADDR/services/data/inputs/http?output_mode=json" \
                    -d name="$HEC_TOKEN_NAME" -d index=telltale -d sourcetype=telltale:json)
            fi
            ADR_LIVETEST_HEC_TOKEN=$(printf '%s' "$token_json" \
                | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["entry"][0]["content"]["token"])' 2>/dev/null || true)
            if [ -n "$ADR_LIVETEST_HEC_TOKEN" ]; then
                export ADR_LIVETEST_HEC_TOKEN
                # HEC may serve TLS with a self-signed cert; probe scheme.
                HEC_SCHEME=https
                curl -sk -m 5 -o /dev/null "https://$HEC_ADDR/services/collector/health" || HEC_SCHEME=http
                HEC_URL="$HEC_SCHEME://$HEC_ADDR/services/collector"
                SPLUNK_AVAILABLE=true
                echo "Splunk HEC ready at $HEC_URL (token '$HEC_TOKEN_NAME')"
            else
                echo "WARN: could not obtain a HEC token; skipping Splunk sink" >&2
            fi
        else
            echo "WARN: Splunk container missing password or published ports; skipping" >&2
        fi
    else
        echo "WARN: Splunk container did not become healthy; skipping Splunk sink" >&2
    fi
else
    note "Splunk container '$SPLUNK_CONTAINER' not found; testing Elasticsearch only"
fi

# ------------------------------------------------- generate gitignored config
note "Writing gitignored outputs config to $OUT_DIR"
mkdir -p "$OUT_DIR"
rm -f "$STATE_PATH" "$LOG_PATH"
{
    cat <<EOF
# Generated by scripts/dev/live-emitter-test.sh — lives in gitignored local/.
version: 1
sinks:
  - name: local
    type: jsonl
    path: $LOG_PATH
  - name: livetest-elastic
    type: elastic_bulk
    endpoint: $ES_URL
    index: $ES_INDEX
    username: elastic
    password: { env: ADR_LIVETEST_ES_PASSWORD }
    retry: { max_attempts: 3, base_delay_ms: 250 }
EOF
    if $SPLUNK_AVAILABLE; then
        cat <<EOF
  - name: livetest-splunk
    type: splunk_hec
    endpoint: $HEC_URL
    token: { env: ADR_LIVETEST_HEC_TOKEN }
    index: telltale
    sourcetype: telltale:json
    retry: { max_attempts: 3, base_delay_ms: 250 }
EOF
        if [ "$HEC_SCHEME" = https ]; then
            cat <<'EOF'
    tls: { insecure_skip_verify: true }   # local self-signed HEC cert
EOF
        fi
    fi
} > "$OUT_DIR/live.yaml"

# ------------------------------------------------------------------ run scan
note "Building adr and validating outputs config"
cargo build --quiet --manifest-path "$REPO_ROOT/Cargo.toml"
ADR="$REPO_ROOT/target/debug/adr"
"$ADR" config validate --config-dir "$LOCAL_DIR" | python3 -m json.tool | sed -n '/"outputs"/,/^    }/p'

note "Running fixture scan through live sinks"
"$ADR" scan --once --allow-fixtures \
    --root "$REPO_ROOT/tests/fixtures/session_stores" \
    --config-dir "$LOCAL_DIR" \
    --log-path "$LOG_PATH" \
    --state-path "$STATE_PATH" \
    --install-inventory-disabled

EVENT_COUNT=$(wc -l < "$LOG_PATH")
echo "Local JSONL events written: $EVENT_COUNT"

# -------------------------------------------------------------- verification
note "Verifying Elasticsearch delivery"
es_curl -X POST "$ES_URL/$ES_INDEX/_refresh" >/dev/null
ES_COUNT=$(es_curl "$ES_URL/$ES_INDEX/_count" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
echo "Elasticsearch $ES_INDEX doc count: $ES_COUNT (expected $EVENT_COUNT)"
[ "$ES_COUNT" = "$EVENT_COUNT" ] || fail "Elasticsearch count mismatch"

SAMPLE_ID=$(head -1 "$LOG_PATH" | python3 -c 'import json,sys; print(json.load(sys.stdin)["event_id"])')
SAMPLE_TYPE=$(es_curl "$ES_URL/$ES_INDEX/_doc/$SAMPLE_ID" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["_source"]["event_type"] if d.get("found") else "MISSING")')
echo "Sample doc _id=$SAMPLE_ID event_type=$SAMPLE_TYPE"
[ "$SAMPLE_TYPE" != "MISSING" ] || fail "sample event not found in Elasticsearch by event_id"
echo "PASS: Elasticsearch sink"

if $SPLUNK_AVAILABLE; then
    note "Verifying Splunk delivery (search may lag a few seconds)"
    HEALTH_ID=$(python3 - "$LOG_PATH" <<'PYEOF'
import json, sys
for line in open(sys.argv[1]):
    event = json.loads(line)
    if event.get("event_type") == "health":
        print(event["event_id"]); break
PYEOF
)
    SPLUNK_COUNT=0
    for _ in $(seq 1 20); do
        SPLUNK_COUNT=$(mgmt "https://$MGMT_ADDR/services/search/jobs/export" \
            -d output_mode=json -d earliest_time=-10m \
            --data-urlencode "search=search index=telltale \"$HEALTH_ID\" | stats count" \
            | python3 -c 'import json,sys
count = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: d = json.loads(line)
    except ValueError: continue
    if isinstance(d.get("result"), dict) and "count" in d["result"]:
        count = d["result"]["count"]
print(count)' || echo 0)
        [ "${SPLUNK_COUNT:-0}" -ge 1 ] 2>/dev/null && break
        sleep 3
    done
    echo "Splunk events matching this run's health event_id: $SPLUNK_COUNT"
    [ "${SPLUNK_COUNT:-0}" -ge 1 ] 2>/dev/null || fail "health event not found in Splunk index=telltale"
    echo "PASS: Splunk HEC sink"
fi

note "All live sink tests passed"

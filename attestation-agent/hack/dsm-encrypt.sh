#!/usr/bin/env bash
#
# encrypt.sh
#
# Starts the DSM-backed coco_keyprovider, encrypts a container image with skopeo
# (per-layer keys wrapped by a non-exportable KEK in Fortanix DSM), verifies the
# result, then stops the keyprovider and cleans up.
#
# Usage:
#   ./encrypt.sh \
#       --fortanix-dsm-config dsm-config.json \
#       --input-image  nginx:latest \
#       --output-image oci:./nginx-enc:latest \
#       --encrypt-layer 0,1
#
# Layer selection follows skopeo semantics:
#   omitted / "all"  -> every layer is encrypted (skopeo default when
#                       --encryption-key is given and --encrypt-layer is absent)
#   "0,1"            -> encrypt layers 0 and 1 only
#   "-1"             -> encrypt the LAST layer only (negative = from the end)
#
# The equivalent raw command is:
#   OCICRYPT_KEYPROVIDER_CONFIG=/tmp/kp.yaml skopeo copy --insecure-policy \
#       --encrypt-layer 0,1 --encryption-key provider:attestation-agent \
#       docker://nginx:latest docker://<dest>:tag
#
# DSM config, JSON or YAML, auto-detected from content:
#   {
#     "api-endpoint": "https://sit.smartkey.io",
#     "api-key": "<DSM_API_KEY>"
#   }
#
#   api-endpoint: https://sit.smartkey.io
#   api-key: <DSM_API_KEY>
#
# Image refs may be bare (treated as docker://) or carry a skopeo transport
# prefix (docker://, oci:, oci-archive:, dir:, docker-archive:, ...).
#
set -euo pipefail

SCRIPT_NAME=$(basename "$0")

# ---- defaults ---------------------------------------------------------------
SOCKET="127.0.0.1:50000"
KP_BIN=""
KEYID=""
KEK_MODE=""                 # "" = keyprovider default (per-layer) | shared | per-layer
KEK_NAME=""                 # DSM sobject name for the KEK(s) created
ENCRYPT_LAYER="all"         # "all" | comma-separated indices, negatives allowed
DSM_CONFIG=""
INPUT_IMAGE=""
OUTPUT_IMAGE=""
DEST_TLS_VERIFY=""          # "true"/"false" passthrough for docker:// dests
READY_TIMEOUT=30            # seconds to wait for the keyprovider socket

die() { echo "[!] $*" >&2; exit 1; }

usage() {
  cat <<EOF
$SCRIPT_NAME: encrypt a container image using the DSM coco_keyprovider

Required:
  --fortanix-dsm-config <file>   JSON *or* YAML with "api-endpoint" and "api-key"
                                 (format auto-detected from the file contents)
  --input-image  <ref>           source image (bare => docker://)
  --output-image <ref>           destination (bare => docker://; or oci:./dir:tag)

Optional:
  --keyprovider-bin <path>       coco_keyprovider binary (default: ./coco_keyprovider or \$PATH)
  --socket <host:port>           keyprovider gRPC socket (default: $SOCKET)
  --keyid <uuid|kbs:///dsm/key/uuid>
                                 reuse an existing DSM KEK (default: create a new one).
                                 Implies one KEK for the whole image.
  --kek-mode <shared|per-layer>  how many KEKs to create in DSM for this image:
                                   per-layer => one new KEK per encrypted layer
                                                (keyprovider default)
                                   shared    => one KEK wraps every layer
                                 Revoking a KEK in DSM makes its layer(s)
                                 undecryptable, so 'shared' revokes the whole
                                 image at once, 'per-layer' one layer at a time.
  --kek-name <name>              DSM sobject name for the KEK(s) created
                                 (default: ccm-kbc-kek-<uuid>). In per-layer mode
                                 the layer index is appended: <name>-0, <name>-1...
  --encrypt-layer <spec>         "all" (default) | comma-separated 0-indexed layer
                                 indices, negatives count from the end.
                                   all   => every layer
                                   0,1   => first two layers
                                   -1    => last layer only
  --dest-tls-verify <true|false> passthrough to skopeo for docker:// dests
  --ready-timeout <seconds>      keyprovider startup wait (default: $READY_TIMEOUT)
  -h, --help

Flags accept both "--flag value" and "--flag=value".

Examples:
  # all layers, one new KEK per layer (default)
  $SCRIPT_NAME --fortanix-dsm-config dsm-config.json \\
      --input-image nginx:latest --output-image oci:./nginx-enc:latest

  # layers 0 and 1, a single named KEK for the whole image
  $SCRIPT_NAME --fortanix-dsm-config dsm-config.json \\
      --input-image nginx:latest --output-image oci:./nginx-enc:latest \\
      --encrypt-layer 0,1 --kek-mode shared --kek-name nginx-kek

  # reuse a KEK created by an earlier run
  $SCRIPT_NAME --fortanix-dsm-config dsm-config.json \\
      --input-image nginx:latest --output-image oci:./nginx-enc:latest \\
      --keyid kbs:///dsm/key/9a4f5bd3-d3d2-4e88-98c7-eedd9f04eefd
EOF
}

# ---- args -------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    # GNU-style --flag=value: split into "--flag" "value" and re-dispatch
    --*=*)                 set -- "${1%%=*}" "${1#*=}" "${@:2}"; continue;;
    --fortanix-dsm-config) DSM_CONFIG="${2:-}"; shift 2;;
    --input-image)         INPUT_IMAGE="${2:-}"; shift 2;;
    --output-image)        OUTPUT_IMAGE="${2:-}"; shift 2;;
    --keyprovider-bin)     KP_BIN="${2:-}"; shift 2;;
    --socket)              SOCKET="${2:-}"; shift 2;;
    --keyid)               KEYID="${2:-}"; shift 2;;
    --kek-mode)            KEK_MODE="${2:-}"; shift 2;;
    --kek-name)            KEK_NAME="${2:-}"; shift 2;;
    --encrypt-layer)       ENCRYPT_LAYER="${2:-}"; shift 2;;
    --dest-tls-verify)     DEST_TLS_VERIFY="${2:-}"; shift 2;;
    --ready-timeout)       READY_TIMEOUT="${2:-}"; shift 2;;
    -h|--help)             usage; exit 0;;
    *) echo "[!] unknown argument: $1" >&2; usage; exit 2;;
  esac
done

[[ -n "$DSM_CONFIG"  ]] || { usage; die "missing --fortanix-dsm-config"; }
[[ -n "$INPUT_IMAGE" ]] || { usage; die "missing --input-image"; }
[[ -n "$OUTPUT_IMAGE" ]] || { usage; die "missing --output-image"; }
[[ -f "$DSM_CONFIG"  ]] || die "DSM config not found: $DSM_CONFIG"

# ---- KEK selection ----------------------------------------------------------
# --keyid pins one existing KEK, so it is shared across layers by definition;
# a KEK mode or a name to create under would be silently ignored by the
# keyprovider. Reject rather than mislead.
case "$KEK_MODE" in
  ""|shared|per-layer) ;;
  *) die "invalid --kek-mode: '$KEK_MODE' (want 'shared' or 'per-layer')";;
esac
if [[ -n "$KEYID" ]]; then
  [[ -z "$KEK_MODE" ]] || die "--keyid pins one existing KEK; drop --kek-mode $KEK_MODE"
  [[ -z "$KEK_NAME" ]] || die "--keyid reuses an existing KEK; --kek-name would not be used"
fi

# ---- layer spec -------------------------------------------------------------
# ENCRYPT_ALL=1        => omit --encrypt-layer entirely (skopeo encrypts all)
# LAYER_SPEC="0,1"     => value passed verbatim to skopeo
# LAYER_LIST=(0 1)     => parsed indices, resolved against the layer count later
ENCRYPT_ALL=0
LAYER_SPEC=""
declare -a LAYER_LIST=()

parse_layer_spec() {
  local spec="${ENCRYPT_LAYER//[[:space:]]/}"

  # Empty or "all" (any case) => every layer. Do NOT pass --encrypt-layer:
  # skopeo treats an explicit -1 as "the last layer", not "all layers".
  if [[ -z "$spec" || "${spec,,}" == "all" ]]; then
    ENCRYPT_ALL=1
    return
  fi

  [[ "$spec" =~ ^-?[0-9]+(,-?[0-9]+)*$ ]] \
    || die "invalid --encrypt-layer: '$ENCRYPT_LAYER' (want 'all' or comma-separated indices, e.g. 0,1 or -1)"

  local IFS=','
  read -r -a LAYER_LIST <<<"$spec"
  LAYER_SPEC="$spec"
}
parse_layer_spec

# ---- dependencies -----------------------------------------------------------
command -v jq     >/dev/null 2>&1 || die "jq is required (sudo apt-get install jq)"
command -v skopeo >/dev/null 2>&1 || die "skopeo is required"

if [[ -z "$KP_BIN" ]]; then
  if   [[ -x ./coco_keyprovider ]]; then KP_BIN="./coco_keyprovider"
  elif command -v coco_keyprovider >/dev/null 2>&1; then KP_BIN="$(command -v coco_keyprovider)"
  else die "coco_keyprovider not found; pass --keyprovider-bin <path>"
  fi
fi
[[ -x "$KP_BIN" ]] || die "not executable: $KP_BIN"

# this binary must have been built with --features ccm_kbc
if ! "$KP_BIN" --help 2>&1 | grep -q -- '--dsm-endpoint'; then
  die "this coco_keyprovider has no --dsm-endpoint; please ask Fortanix for one which includes ccm_kbc"
fi

# ---- read DSM config (JSON or YAML) -----------------------------------------
# JSON:                       YAML:
#   {                           api-endpoint: https://sit.smartkey.io
#     "api-endpoint": "...",    api-key: <DSM_API_KEY>
#     "api-key": "..."
#   }
# Format is detected from the content (leading '{' => JSON), not the extension,
# so a .json file holding YAML still works. YAML is read with yq if installed,
# otherwise with a minimal flat-key parser (good enough for these two keys).

yaml_get() {   # yaml_get <file> <key>  -> value on stdout, empty if absent
  local file="$1" key="$2"
  if command -v yq >/dev/null 2>&1; then
    yq -r ".\"$key\" // \"\"" "$file" 2>/dev/null
    return
  fi
  # fallback: flat "key: value" at column 0, strips quotes, inline # comments
  sed -n -E "s/^[[:space:]]*${key}[[:space:]]*:[[:space:]]*(.*)\$/\1/p" "$file" \
    | head -n1 \
    | sed -E 's/[[:space:]]+#.*$//; s/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/; s/[[:space:]]+$//'
}

read_config() {
  local first
  first="$(grep -m1 -v -E '^[[:space:]]*(#|$)' "$DSM_CONFIG" || true)"

  if [[ "$first" == *"{"* ]]; then
    CONFIG_FORMAT="json"
    jq -e . "$DSM_CONFIG" >/dev/null 2>&1 || die "config is not valid JSON: $DSM_CONFIG"
    ENDPOINT="$(jq -r '."api-endpoint" // .api_endpoint // .endpoint // empty' "$DSM_CONFIG")"
    APIKEY="$(jq -r '."api-key" // .api_key // .apikey // empty' "$DSM_CONFIG")"
  else
    CONFIG_FORMAT="yaml"
    for k in api-endpoint api_endpoint endpoint; do
      if [[ -z "$ENDPOINT" ]]; then ENDPOINT="$(yaml_get "$DSM_CONFIG" "$k")"; fi
    done
    for k in api-key api_key apikey; do
      if [[ -z "$APIKEY" ]]; then APIKEY="$(yaml_get "$DSM_CONFIG" "$k")"; fi
    done
  fi

  [[ -n "$ENDPOINT" ]] || die "config missing \"api-endpoint\" ($CONFIG_FORMAT): $DSM_CONFIG"
  [[ -n "$APIKEY"   ]] || die "config missing \"api-key\" ($CONFIG_FORMAT): $DSM_CONFIG"
}
ENDPOINT=""; APIKEY=""; CONFIG_FORMAT=""
read_config
echo "[*] DSM config: $DSM_CONFIG ($CONFIG_FORMAT)"

HOST="${SOCKET%%:*}"
PORT="${SOCKET##*:}"

# ---- temp workspace + cleanup ----------------------------------------------
umask 077
WORKDIR="$(mktemp -d)"
APIKEY_FILE="$WORKDIR/apikey"
OCICRYPT_CFG="$WORKDIR/ocicrypt-keyprovider.json"
KP_LOG="$WORKDIR/keyprovider.log"
KP_PID=""

cleanup() {
  if [[ -n "$KP_PID" ]] && kill -0 "$KP_PID" 2>/dev/null; then
    kill "$KP_PID" 2>/dev/null || true
    wait "$KP_PID" 2>/dev/null || true
  fi
  command -v shred >/dev/null 2>&1 && [[ -f "$APIKEY_FILE" ]] && shred -u "$APIKEY_FILE" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

printf '%s' "$APIKEY" > "$APIKEY_FILE"

cat > "$OCICRYPT_CFG" <<EOF
{ "key-providers": { "attestation-agent": { "grpc": "$SOCKET" } } }
EOF

# ---- normalize image transports --------------------------------------------
with_transport() {
  case "$1" in
    docker://*|oci:*|oci-archive:*|dir:*|docker-archive:*|containers-storage:*|docker-daemon:*) printf '%s' "$1";;
    *) printf 'docker://%s' "$1";;
  esac
}
SRC="$(with_transport "$INPUT_IMAGE")"
DST="$(with_transport "$OUTPUT_IMAGE")"

# ---- sanity-check the layer indices against the source ----------------------
# Fail before touching DSM if an index can never match (e.g. --encrypt-layer 5
# on a 3-layer image): skopeo would otherwise copy the image with fewer layers
# encrypted than asked for.
SRC_LAYERS="$(skopeo inspect --raw "$SRC" 2>/dev/null | jq -r '.layers | length' 2>/dev/null || true)"
if [[ "$ENCRYPT_ALL" -eq 0 && "$SRC_LAYERS" =~ ^[0-9]+$ && "$SRC_LAYERS" -gt 0 ]]; then
  for idx in "${LAYER_LIST[@]}"; do
    r=$idx
    (( r < 0 )) && r=$(( SRC_LAYERS + idx ))
    (( r >= 0 && r < SRC_LAYERS )) \
      || die "--encrypt-layer $idx is out of range: $SRC has $SRC_LAYERS layer(s) (valid: 0..$((SRC_LAYERS-1)) or -1..-$SRC_LAYERS)"
  done
fi

# ---- build the ocicrypt encryption-key argument -----------------------------
# ocicrypt syntax: provider:<name>[:<k>=<v>::<k>=<v>...]
# It splits on the FIRST colon after "provider:", so the params must follow the
# provider name behind a colon, not "=", and not base64: ocicrypt base64s the
# params itself when it marshals the gRPC request (the keyprovider decodes them
# in grpc/mod.rs). Encoding here would double-encode and break parse_keyid.
# Done before the keyprovider starts so a bad keyid costs nothing.
ENC_KEY="provider:attestation-agent"
if [[ -n "$KEYID" ]]; then
  # A KBS resource URI is kbs:///<repo>/<type>/<tag>, three segments, or the
  # annotation cannot be parsed. The two-segment kbs:///dsm/<uuid> form was emitted
  # previously; accept it and rewrite, so a recorded kid keeps working.
  case "$KEYID" in
    kbs:///dsm/key/*) kid="$KEYID";;
    kbs:///dsm/*)     kid="kbs:///dsm/key/${KEYID#kbs:///dsm/}"
                      echo "[*] --keyid uses the legacy two-segment form; using $kid";;
    kbs:///*)         die "KBS-style keyid not allowed in DSM mode: $KEYID (use kbs:///dsm/key/<uuid>)";;
    *)                kid="kbs:///dsm/key/$KEYID";;
  esac
  # The keyprovider treats a keyid that is not a DSM kid as the NAME of a KEK to
  # create, so a typo'd id would silently mint a new KEK and encrypt against it,
  # and the image would only fail to decrypt later, on the node.
  uuid="${kid#kbs:///dsm/key/}"
  [[ "$uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
    || die "--keyid must be a DSM KEK UUID or kbs:///dsm/key/<uuid>, got: $KEYID"
  ENC_KEY="provider:attestation-agent:keyid=$kid"
  echo "[*] reusing existing KEK: $kid (one KEK for every layer)"
elif [[ "$KEK_MODE" == "shared" ]]; then
  echo "[*] a single new non-exportable KEK will be created in DSM for all layers"
else
  echo "[*] a new non-exportable KEK will be created in DSM per encrypted layer"
fi

# ---- start keyprovider ------------------------------------------------------
# --kek-mode / --kek-name are keyprovider-side: it is the keyprovider, not
# skopeo, that creates the KEK(s) in DSM (once per layer, or once per image).
declare -a KP_ARGS=( --socket "$SOCKET"
                     --dsm-endpoint "$ENDPOINT"
                     --dsm-api-key-file "$APIKEY_FILE" )
[[ -n "$KEK_MODE" ]] && KP_ARGS+=( --kek-mode "$KEK_MODE" )
[[ -n "$KEK_NAME" ]] && KP_ARGS+=( --kek-name "$KEK_NAME" )

echo "[*] starting coco_keyprovider on $SOCKET"
echo "    endpoint:  $ENDPOINT"
echo "    kek-mode:  ${KEK_MODE:-per-layer (keyprovider default)}"
[[ -n "$KEK_NAME" ]] && echo "    kek-name:  $KEK_NAME"
"$KP_BIN" "${KP_ARGS[@]}" >"$KP_LOG" 2>&1 &
KP_PID=$!

echo "[*] waiting for keyprovider to listen (timeout ${READY_TIMEOUT}s)..."
start=$SECONDS
until timeout 1 bash -c ">/dev/tcp/$HOST/$PORT" 2>/dev/null; do
  if ! kill -0 "$KP_PID" 2>/dev/null; then
    echo "[!] keyprovider exited during startup:" >&2; sed 's/^/    /' "$KP_LOG" >&2; exit 1
  fi
  if (( SECONDS - start >= READY_TIMEOUT )); then
    echo "[!] timed out waiting for keyprovider:" >&2; sed 's/^/    /' "$KP_LOG" >&2; exit 1
  fi
  sleep 0.5
done
echo "[*] keyprovider ready (pid $KP_PID)"

# ---- encrypt ----------------------------------------------------------------
if [[ "$ENCRYPT_ALL" -eq 1 ]]; then
  LAYER_DESC="all layers"
else
  LAYER_DESC="layer(s) $LAYER_SPEC"
fi
echo "[*] encrypting:"
echo "      src: $SRC"
echo "      dst: $DST  ($LAYER_DESC)"
echo "      encryption-key: $ENC_KEY"

declare -a ARGS=( copy --insecure-policy
                  --encryption-key "$ENC_KEY" )
# skopeo: --encrypt-layer omitted => ALL layers. A value is a comma-separated
# list of 0-indexed layers, negatives counting from the end (-1 = last layer).
[[ "$ENCRYPT_ALL" -eq 0 ]] && ARGS+=( --encrypt-layer "$LAYER_SPEC" )
[[ -n "$DEST_TLS_VERIFY" ]] && ARGS+=( --dest-tls-verify="$DEST_TLS_VERIFY" )
ARGS+=( "$SRC" "$DST" )

OCICRYPT_KEYPROVIDER_CONFIG="$OCICRYPT_CFG" skopeo "${ARGS[@]}"
echo "[*] encryption complete"

# ---- verify the requested layers really are encrypted -----------------------
# skopeo can exit 0 with plaintext layers on some key-provider failures, so
# assert the destination manifest instead of trusting the exit code.
INSPECT_TLS=()
[[ -n "$DEST_TLS_VERIFY" ]] && INSPECT_TLS+=( --tls-verify="$DEST_TLS_VERIFY" )

RAW="$(skopeo inspect --raw "${INSPECT_TLS[@]}" "$DST" 2>/dev/null)" \
  || die "could not inspect destination to verify encryption: $DST"

mapfile -t MEDIA < <(printf '%s' "$RAW" | jq -r '.layers[].mediaType')
TOTAL="${#MEDIA[@]}"
(( TOTAL > 0 )) || die "destination has no layers to verify: $DST"

is_enc() { [[ "$1" == *"+encrypted" ]]; }

ENC_COUNT=0
for m in "${MEDIA[@]}"; do is_enc "$m" && ENC_COUNT=$((ENC_COUNT + 1)); done

if [[ "$ENCRYPT_ALL" -eq 1 ]]; then
  (( ENC_COUNT == TOTAL )) \
    || die "encryption verification FAILED: only $ENC_COUNT/$TOTAL layers encrypted in $DST"
  echo "[*] verified: all $TOTAL layers encrypted"
else
  # resolve negatives against the real layer count, then check each one
  declare -a WANT=()
  for idx in "${LAYER_LIST[@]}"; do
    r=$idx
    (( r < 0 )) && r=$(( TOTAL + idx ))
    (( r >= 0 && r < TOTAL )) \
      || die "--encrypt-layer $idx is out of range: image has $TOTAL layer(s)"
    WANT+=( "$r" )
  done
  mapfile -t WANT < <(printf '%s\n' "${WANT[@]}" | sort -nu)

  for r in "${WANT[@]}"; do
    is_enc "${MEDIA[$r]}" \
      || die "encryption verification FAILED: layer $r is NOT encrypted (${MEDIA[$r]}) in $DST"
  done
  (( ENC_COUNT == ${#WANT[@]} )) \
    || echo "[!] warning: $ENC_COUNT layers encrypted but ${#WANT[@]} requested; extra encrypted layers present" >&2
  echo "[*] verified: layer(s) ${WANT[*]} encrypted ($ENC_COUNT/$TOTAL total)"
fi

# ---- report the KEK(s) the layers were wrapped with --------------------------
# One kid per encrypted layer; how many DISTINCT kids appear is exactly the
# shared-vs-per-layer outcome, so report the count, not just the list.
mapfile -t KIDS < <(printf '%s' "$RAW" \
  | jq -r '.layers[]?.annotations["org.opencontainers.image.enc.keys.provider.attestation-agent"] // empty' \
  | while read -r p; do
      [[ -n "$p" ]] && printf '%s' "$p" | base64 -d 2>/dev/null | jq -r '.kid' 2>/dev/null
    done)
mapfile -t UNIQ_KIDS < <(printf '%s\n' "${KIDS[@]}" | grep -v '^$' | sort -u)

echo "[*] ${#KIDS[@]} encrypted layer(s), ${#UNIQ_KIDS[@]} distinct KEK(s) in DSM:"
printf '      %s\n' "${UNIQ_KIDS[@]}"

# also surface anything the keyprovider logged about the KEK(s) it used
if grep -iqE 'kbs:///dsm|KEK' "$KP_LOG"; then
  echo "[*] keyprovider notes:"
  grep -iE 'kbs:///dsm|KEK' "$KP_LOG" | sed 's/^/      /' || true
fi

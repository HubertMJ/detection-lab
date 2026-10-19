#!/bin/sh
# The lab VM's boot action (variant B). A systemd oneshot runs this at every boot: run the scenario,
# wait until Fluent Bit has shipped every event to siem01, then power the VM off. The VM is reverted
# to a clean snapshot before each boot, so this is the whole life of a run.
#
# Config comes from the environment (set by the unit the provisioning installs); no secret here.
#   LAB_BASE      compiled base image (copy 1)          default /opt/lab/lab-canary
#   LAB_SINK_IP   beacon sink = siem01                  required
#   LAB_SINK_PORT                                       default 8080
#   LAB_BEACONS   beacons per copy (>=5)                default 6
#   LAB_INTERVAL_MS                                     default 20000
#   LAB_GAP_S     seconds between copies                default 15
#   LAB_NAMEMAP   name map Fluent Bit reads             default /run/lab/namemap
#   FB_METRICS    Fluent Bit metrics URL                default http://127.0.0.1:2020/api/v1/metrics
#   DRAIN_TIMEOUT max seconds to wait for the ship       default 300
#   NO_POWEROFF   set to 1 to skip poweroff (testing)
set -eu

BASE=${LAB_BASE:-/opt/lab/lab-canary}
SINK_IP=${LAB_SINK_IP:?LAB_SINK_IP (siem01) is required}
SINK_PORT=${LAB_SINK_PORT:-8080}
BEACONS=${LAB_BEACONS:-6}
INTERVAL_MS=${LAB_INTERVAL_MS:-20000}
GAP_S=${LAB_GAP_S:-15}
NAMEMAP=${LAB_NAMEMAP:-/run/lab/namemap}
FB_METRICS=${FB_METRICS:-http://127.0.0.1:2020/api/v1/metrics}
DRAIN_TIMEOUT=${DRAIN_TIMEOUT:-300}

log() { echo "run-and-ship: $*"; }

# Sum every output's proc_records (records handed to an output) from Fluent Bit's metrics: the
# simplest "did it ship" signal. -1 if the endpoint is not answering yet.
sent_count() {
  curl -s --max-time 5 "$FB_METRICS" 2>/dev/null \
    | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)
except Exception:
    print(-1); raise SystemExit
out=d.get("output",{})
print(sum(int(v.get("proc_records",0)) for v in out.values()) if isinstance(out,dict) else -1)' 2>/dev/null || echo -1
}

# Wait until the shipped count has stopped rising for a few checks (everything drained), bounded.
drain() {
  log "waiting for Fluent Bit to drain (timeout ${DRAIN_TIMEOUT}s)"
  last=-1 ; stable=0 ; waited=0
  while [ "$waited" -lt "$DRAIN_TIMEOUT" ]; do
    now=$(sent_count)
    if [ "$now" -ge 0 ] && [ "$now" = "$last" ] && [ "$now" -gt 0 ]; then
      stable=$((stable + 1))
      [ "$stable" -ge 3 ] && { log "drained at $now records"; return 0; }
    else
      stable=0
    fi
    last=$now
    sleep 5 ; waited=$((waited + 5))
  done
  log "drain timeout after ${waited}s (last count $last); powering off anyway"
}

log "starting scenario (sink ${SINK_IP}:${SINK_PORT})"
python3 /opt/lab/run_scenario.py \
  --base "$BASE" --workdir /tmp \
  --sink-ip "$SINK_IP" --sink-port "$SINK_PORT" \
  --beacons "$BEACONS" --interval-ms "$INTERVAL_MS" --gap-s "$GAP_S" \
  --namemap "$NAMEMAP"

drain

if [ "${NO_POWEROFF:-0}" = "1" ]; then
  log "NO_POWEROFF set; not powering off"
else
  log "powering off"
  systemctl poweroff
fi

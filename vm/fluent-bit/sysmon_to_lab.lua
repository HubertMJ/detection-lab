-- Fluent Bit filter: Sysmon for Linux (journald) -> the sdp-lab event shape (variant B).
--
-- Sysmon for Linux logs each event to the journal as a Windows-Sysmon XML document in MESSAGE. This
-- turns the three events the lab cares about (1 process-create, 3 network-connection, 11 file-create)
-- into the exact sdp-lab fields variant A produces, so the SAME detector and monitor catch them.
--
-- It ships ONLY this run's canary events: every record whose Image is not one of the run's copy
-- names (written by run_scenario.py as the name map) is dropped, so none of the VM's other activity
-- leaves the host. It also masks: host.name -> "lab-vm", and the beacon destination -> the same
-- synthetic TEST-NET-2 address variant A indexes (198.51.100.10, never the real sink address), so
-- the polymorphic-beacon monitor groups both variants alike.
--
-- Sysmon for Linux's network-connection event carries no Hashes, so event 3 takes the copy's
-- SHA-256 from the name map (run_scenario knows it before the copy runs): the monitor counts distinct
-- hashes per beacon address. Records leave nested ({"event":{"code":..}}): Security Analytics only
-- matches nested documents, as variant A's indexer.nest does.
--
-- The pure mapping (parse_xml / map / nest) takes no I/O and is tested offline with fixtures
-- (test_mapper.lua); only cb_sysmon touches Fluent Bit records and the name-map file.

local M = {}

local NAMEMAP_PATH = os.getenv("LAB_NAMEMAP") or "/run/lab/namemap"
local HOST = "lab-vm"
-- RFC 5737 TEST-NET-2, the beacon address variant A indexes (lab/generate.py --beacon-ip).
local BEACON_MASK = os.getenv("LAB_BEACON_MASK") or "198.51.100.10"
local ACTION = { ["1"] = "process-create", ["3"] = "network-connection", ["11"] = "file-create" }

-- "2026-10-19 07:36:10.123" (Sysmon UtcTime) -> "2026-10-19T07:36:10.123Z".
local function utc_iso(utc)
  if not utc then return nil end
  local d, t = utc:match("^(%d%d%d%d%-%d%d%-%d%d)%s+([%d:%.]+)$")
  if not d then return nil end
  if not t:find("%.") then t = t .. ".000" end
  return d .. "T" .. t .. "Z"
end

local function basename(p)
  if not p then return nil end
  return (p:match("([^/]+)$")) or p
end

-- All <Data Name="x">v</Data> pairs (either quote), plus the EventID, from a Sysmon XML string.
function M.parse_xml(xml)
  if not xml then return nil end
  local ev = { event_id = xml:match("<EventID>(%d+)</EventID>"), data = {} }
  if not ev.event_id then return nil end
  for name, val in xml:gmatch("<Data Name=['\"](.-)['\"]>(.-)</Data>") do
    ev.data[name] = val
  end
  return ev
end

-- One parsed Sysmon event + the run context {run_id, names={[name]=variant}, hashes={[name]=sha}}
-- -> a flat sdp-lab record,
-- or nil when the event is not one we ship (unknown id, or an image outside this run's copies).
-- Keyed by the copy's file name (every event type carries Image), which is known before the copies
-- run, so no early event is lost waiting for a pid.
function M.map(ev, ctx)
  if not ev then return nil end
  local code = ev.event_id
  if not ACTION[code] then return nil end
  local d = ev.data
  local name = basename(d.Image)
  if not name then return nil end
  local variant = ctx.names[name]
  if not variant then return nil end
  local pid = tonumber(d.ProcessId)

  local out = {
    ["@timestamp"] = utc_iso(d.UtcTime),
    ["event.kind"] = "event",
    ["event.dataset"] = "lab",
    ["event.code"] = code,
    ["event.action"] = ACTION[code],
    ["lab.run_id"] = ctx.run_id,
    ["lab.mode"] = "isolated-vm",
    ["lab.variant"] = variant,
    ["host.name"] = HOST,
    ["process.pid"] = pid,
    ["process.name"] = basename(d.Image),
    ["process.executable"] = d.Image,
  }
  if code == "1" then
    local sha = d.Hashes and d.Hashes:match("SHA256=([0-9A-Fa-f]+)")
    if sha then out["process.hash.sha256"] = sha:lower() end
    if d.ParentImage then out["process.parent.name"] = basename(d.ParentImage) end
    local ppid = tonumber(d.ParentProcessId)
    if ppid then out["process.parent.pid"] = ppid end
  elseif code == "11" then
    out["file.path"] = d.TargetFilename
  elseif code == "3" then
    -- Linux Sysmon has no Hashes on event 3; the name map carries each copy's SHA-256.
    local sha = d.Hashes and d.Hashes:match("SHA256=([0-9A-Fa-f]+)")
    sha = (sha and sha:lower()) or (ctx.hashes and ctx.hashes[name])
    if sha then out["process.hash.sha256"] = sha end
    local port = tonumber(d.DestinationPort)
    -- Mask the real sink address: the monitor groups by destination.ip/port, and variant A indexes
    -- this same synthetic address, so both variants open the incident the same way.
    out["destination.ip"] = BEACON_MASK
    out["destination.port"] = port
  end
  return out
end

-- Flat dotted keys -> nested tables ("@timestamp" stays top level), like variant A's indexer.nest.
function M.nest(flat)
  local out = {}
  for key, value in pairs(flat) do
    if key == "@timestamp" then
      out[key] = value
    else
      local node = out
      local parts = {}
      for part in key:gmatch("[^.]+") do parts[#parts + 1] = part end
      for i = 1, #parts - 1 do
        node[parts[i]] = node[parts[i]] or {}
        node = node[parts[i]]
      end
      node[parts[#parts]] = value
    end
  end
  return out
end

-- Load {run_id, names, hashes} from the name-map file (run_id on the first line, then
-- "name variant [sha256]" lines), cached and reloaded when the file's content changes. Returns nil
-- until run_scenario has written it.
local _cache = { sig = nil, ctx = nil }
local function load_ctx(path)
  local f = io.open(path or NAMEMAP_PATH, "r")
  if not f then return nil end
  local body = f:read("*a")
  f:close()
  if body == _cache.sig then return _cache.ctx end
  local ctx = { run_id = nil, names = {}, hashes = {} }
  for line in body:gmatch("[^\n]+") do
    if not ctx.run_id then
      ctx.run_id = line:match("^run_id%s+(%S+)")
    else
      -- "name variant" or "name variant <64-hex sha256>"
      local name, variant = line:match("^(%S+)%s+(%d+)%s*$")
      local sha
      if not name then name, variant, sha = line:match("^(%S+)%s+(%d+)%s+(%x+)%s*$") end
      if name then
        ctx.names[name] = tonumber(variant)
        if sha and #sha == 64 then ctx.hashes[name] = sha:lower() end
      end
    end
  end
  if not ctx.run_id then return nil end
  _cache.sig, _cache.ctx = body, ctx
  return ctx
end

-- Fluent Bit entry point. Returns -1 to drop, or 1 with the rewritten record.
function cb_sysmon(tag, ts, record)
  local ctx = load_ctx()
  if not ctx then return -1, ts, record end
  local ev = M.parse_xml(record["MESSAGE"] or record["message"])
  local out = ev and M.map(ev, ctx) or nil
  if not out then return -1, ts, record end
  return 1, ts, M.nest(out)
end

M._load_ctx = load_ctx  -- exposed for the offline tests
return M

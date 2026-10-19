#!/usr/bin/env lua5.1
-- Offline tests for the Sysmon -> sdp-lab Lua mapper. No Fluent Bit, no journal: real Sysmon for
-- Linux XML lines -> expected sdp-lab records. Run: lua5.1 test_mapper.lua
local here = arg[0]:match("^(.*/)") or "./"
local M = dofile(here .. "sysmon_to_lab.lua")

local ctx = { run_id = "lab-20261019T073610Z-39090f",
              names = { ["update-helper"] = 1, ["svc-2b3c5535"] = 2 } }

-- Real Linux-Sysmon XML (trimmed to the fields that matter; order and quoting as sysmon emits).
local EV1 = [[<Event><System><Provider Name="Linux-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2026-10-19T07:36:10.123456Z"/><Execution ProcessID="100" ThreadID="100"/><Computer>lab-vm.internal</Computer></System><EventData><Data Name="RuleName">-</Data><Data Name="UtcTime">2026-10-19 07:36:10.123</Data><Data Name="ProcessId">1234</Data><Data Name="Image">/tmp/update-helper</Data><Data Name="Hashes">SHA256=4850C01E9E5CDB54B604908952B56F246E661DBEC01ED85C19E349CE1BA92F2E</Data><Data Name="ParentProcessId">1000</Data><Data Name="ParentImage">/usr/bin/bash</Data></EventData></Event>]]

local EV11 = [[<Event><System><EventID>11</EventID></System><EventData><Data Name="UtcTime">2026-10-19 07:36:10.456</Data><Data Name="ProcessId">1234</Data><Data Name="Image">/tmp/update-helper</Data><Data Name="TargetFilename">/home/labuser/.config/systemd/user/update-helper.service</Data></EventData></Event>]]

local EV3 = [[<Event><System><EventID>3</EventID></System><EventData><Data Name="UtcTime">2026-10-19 07:36:15.000</Data><Data Name="ProcessId">1234</Data><Data Name="Image">/tmp/update-helper</Data><Data Name="Hashes">SHA256=4850C01E9E5CDB54B604908952B56F246E661DBEC01ED85C19E349CE1BA92F2E</Data><Data Name="Protocol">tcp</Data><Data Name="SourceIp">10.4.2.20</Data><Data Name="SourcePort">44000</Data><Data Name="DestinationIp">10.4.2.10</Data><Data Name="DestinationPort">8080</Data></EventData></Event>]]

-- An event from a pid outside this run (noise) and an event type we do not ship.
local NOISE = [[<Event><System><EventID>1</EventID></System><EventData><Data Name="UtcTime">2026-10-19 07:36:10.000</Data><Data Name="ProcessId">999</Data><Data Name="Image">/usr/lib/systemd/systemd</Data></EventData></Event>]]
local UNSHIPPED = [[<Event><System><EventID>5</EventID></System><EventData><Data Name="UtcTime">2026-10-19 07:36:10.000</Data><Data Name="ProcessId">1234</Data><Data Name="Image">/tmp/update-helper</Data></EventData></Event>]]

local fails = 0
local function check(name, cond)
  if cond then
    print("ok   " .. name)
  else
    print("FAIL " .. name); fails = fails + 1
  end
end

local function m(xml) return M.map(M.parse_xml(xml), ctx) end

-- event 1: process-create
local e1 = m(EV1)
check("ev1 mapped", e1 ~= nil)
check("ev1 code", e1["event.code"] == "1")
check("ev1 action", e1["event.action"] == "process-create")
check("ev1 timestamp", e1["@timestamp"] == "2026-10-19T07:36:10.123Z")
check("ev1 run_id", e1["lab.run_id"] == ctx.run_id)
check("ev1 mode", e1["lab.mode"] == "isolated-vm")
check("ev1 variant", e1["lab.variant"] == 1)
check("ev1 host masked", e1["host.name"] == "lab-vm")
check("ev1 pid", e1["process.pid"] == 1234)
check("ev1 name", e1["process.name"] == "update-helper")
check("ev1 exe", e1["process.executable"] == "/tmp/update-helper")
check("ev1 hash lowercased", e1["process.hash.sha256"] == "4850c01e9e5cdb54b604908952b56f246e661dbec01ed85c19e349ce1ba92f2e")
check("ev1 parent", e1["process.parent.name"] == "bash")
check("ev1 no file.path", e1["file.path"] == nil)

-- event 11: file-create (persistence)
local e11 = m(EV11)
check("ev11 mapped", e11 ~= nil)
check("ev11 code", e11["event.code"] == "11")
check("ev11 action", e11["event.action"] == "file-create")
check("ev11 file.path", e11["file.path"] == "/home/labuser/.config/systemd/user/update-helper.service")
check("ev11 no hash", e11["process.hash.sha256"] == nil)

-- event 3: network-connection (beacon), destination masked
local e3 = m(EV3)
check("ev3 mapped", e3 ~= nil)
check("ev3 code", e3["event.code"] == "3")
check("ev3 action", e3["event.action"] == "network-connection")
check("ev3 dest masked (no real sink ip)", e3["destination.ip"] == "lab beacon :8080")
check("ev3 dest port", e3["destination.port"] == 8080)
check("ev3 real sink ip absent", not tostring(e3["destination.ip"]):find("10%.4%.2%.10"))

-- noise and unshipped events are dropped
check("noise image dropped", m(NOISE) == nil)
check("unshipped eventid dropped", m(UNSHIPPED) == nil)
check("garbage dropped", M.map(M.parse_xml("not xml"), ctx) == nil)

-- the name-map file parses into {run_id, names}
local tmp = os.tmpname()
local tf = io.open(tmp, "w")
tf:write("run_id lab-20261019T073610Z-39090f\nupdate-helper 1\nsvc-2b3c5535 2\nsvc-edc22232 3\n")
tf:close()
local loaded = M._load_ctx(tmp)
os.remove(tmp)
check("namemap run_id", loaded and loaded.run_id == "lab-20261019T073610Z-39090f")
check("namemap names", loaded and loaded.names["update-helper"] == 1 and loaded.names["svc-edc22232"] == 3)
check("namemap missing file -> nil", M._load_ctx("/nonexistent/namemap/xyz") == nil)

if fails == 0 then print("\nALL OK") else print("\n" .. fails .. " FAILED"); os.exit(1) end

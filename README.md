# detection-lab

An incident generator for SIEM training: emulated attacks with a known ground truth, and the
detections that should catch them. The flagship case is polymorphism: every copy of a harmless test
program gets a new hash and a new name, the hash rule misses all but the first, and detection keyed
on behaviour still opens one incident.

**Status: plan and design preview. No generator code exists yet.**

| What | Where |
|---|---|
| A synthetic replay of scenario C, the data behind the preview | [replay/scenario-c.json](replay/scenario-c.json) |
| The preview on the site | https://hubertjablon.ski/lab/ (source: [hubertjablon.ski](https://github.com/HubertMJ/hubertjablon.ski)) |

## Decisions (2026-10-14)

- The Windows lab (GOAD) is not built on the current hardware: it needs roughly 28-36 GB of RAM.
- The SIEM is the OpenSearch instance of
  [self-defending-portfolio](https://github.com/HubertMJ/self-defending-portfolio) (Security
  Analytics with Sigma rules, Alerting monitors).
- Copies are renamed by default, not only rebuilt: a real attacker changes the name too. Risk
  scored per program name never reaches the threshold; scored per behaviour (the address every
  copy calls) it opens one incident at the second copy.
- A synthetic replay is the possible next step: the generator writes Sysmon-format events
  (`replay/`) that can be indexed into OpenSearch without any Windows machine.

## The replay format

`replay/scenario-c.json` (`schema: 1`, `sample: true`): the artefact, the beacon address, the risk
threshold, the rules with their score and ATT&CK technique, and four variants. Each variant has its
host, SHA-256, renamed file name, Sysmon-style events (`event.code` 1, 3, 13), ground truth and the
findings each rule would raise, with the delay to detection. Every value is generated; no machine
ran it.

## License

MIT, see [LICENSE](LICENSE). Planned dependencies keep their own licenses (GOAD GPL-3.0,
Sigma rules DRL 1.1) and are to be used as submodules, not copied.

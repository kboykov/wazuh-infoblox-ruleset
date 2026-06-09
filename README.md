# Wazuh ruleset for Infoblox Data Connector (BloxOne Threat Defense / Universal DDI)

Decoders and rules for ingesting **Infoblox Data Connector** CEF syslog into
[Wazuh](https://wazuh.com). Covers DNS resolution telemetry, DNS Firewall / RPZ
threat events, DHCP lease activity and BloxOne service logs, with security
detections for DGA, DNS tunneling/exfiltration, DHCP starvation and RPZ policy
hits — mapped to MITRE ATT&CK.

Field mappings are derived from the official Infoblox documentation and verified
against a live 2.1.3 Data Connector capture.

- [DNS Query/Response Log Message Mapping](https://docs.infoblox.com/space/BloxOneThreatDefense/35406922)
- [DNS Security Policy Hit and RPZ Hit Log Message Mapping](https://docs.infoblox.com/space/BloxOneThreatDefense/35438586)
- [DHCP Message Mapping](https://docs.infoblox.com/space/BloxOneThreatDefense/35472716)
- [Event Field Logs](https://docs.infoblox.com/space/BloxOneThreatDefense/770048012)

---

## Log source format

The Data Connector emits RFC5424 syslog with the CEF payload in the message body:

```
<134>1 2026-06-08T18:20:08Z host dataconnector - RPZ-QNAME-REDIRECT - CEF:0|Infoblox|Data Connector|2.1.3|RPZ-QNAME-REDIRECT|RPZ EVENT QNAME REDIRECT|8|key=value key=value ...
```

The CEF header `NAME` field (5th `|`-delimited field) encodes the event family
and, for RPZ, the trigger type + policy action (e.g. `RPZ-QNAME-NXDOMAIN`).
Decoders anchor on the CEF header rather than the syslog app-name, because
app-name extraction is not consistent across syslog collectors.

Point your Data Connector at a Wazuh manager/worker syslog listener:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>0.0.0.0/0</allowed-ips>
</remote>
```

---

## What's covered

| Event family            | CEF NAME header          | Decoded | Rules |
|-------------------------|--------------------------|---------|-------|
| DNS Response            | `DNS Response`           | ✅      | 118001–118007 |
| DNS Firewall / RPZ      | `RPZ-*` (all trigger types) | ✅   | 118010–118017 |
| DHCP lease              | `DHCP-LEASE-*`           | ✅      | 118020–118022 |
| BloxOne service log     | `BloxOne-Service-Log`    | ✅      | 118030–118031 |
| Audit logs              | _(pre-staged, commented)_ | ⏸️     | 118040–118041 |
| SOC Insights            | _(pre-staged, commented)_ | ⏸️     | 118050 |

> **Pre-staged** sections are shipped commented out. They are documented from
> the Infoblox field reference but **the in-payload field order is unverified**
> because these event types are not forwarded by default. Enable them in the
> Data Connector traffic-flow config, capture a sample, confirm the decoder
> regex, then uncomment both the decoder and the rules.

---

## Rule reference

IDs occupy the `118000–118099` block. `118000` is the silent base rule; every
other rule chains from it.

### DNS

| ID     | Level | Fires on | MITRE |
|--------|-------|----------|-------|
| 118000 | 0  | Any Infoblox CEF event (base)                        | — |
| 118001 | 0  | DNS NOERROR (telemetry)                               | — |
| 118002 | 3  | DNS NXDOMAIN                                          | — |
| 118003 | 10 | 20+ NXDOMAIN from one client in 60s — **DGA malware** | T1568.002 |
| 118004 | 5  | DNS SERVFAIL / REFUSED                                | — |
| 118005 | 8  | 15+ SERVFAIL/REFUSED from one client in 60s          | — |
| 118006 | 0  | Successful TXT/NULL lookup (telemetry)               | — |
| 118007 | 11 | 40+ TXT/NULL from one client in 60s — **DNS tunneling/exfil** | T1048.003, T1071.004 |

### RPZ / DNS Firewall

| ID     | Level | Fires on | MITRE |
|--------|-------|----------|-------|
| 118010 | 8  | Any RPZ hit (policy action present)                  | T1071.004 |
| 118014 | 9  | RPZ hit, threat level **30–79 (Medium)**             | T1071.004 |
| 118011 | 12 | RPZ hit, threat level **80–100 (High)**              | T1071.004 |
| 118012 | 12 | RPZ threat property = malware / C2 / phishing / botnet | T1071.004, T1568.001 |
| 118013 | 10 | 10+ RPZ hits from one client in 120s — infected host | T1071.004, T1568.001 |
| 118016 | 10 | RPZ action = Block / NXDOMAIN / NODATA               | T1071.004 |
| 118017 | 6  | RPZ action = Passthru / Log (allowlist override)     | — |

### DHCP

| ID     | Level | Fires on | MITRE |
|--------|-------|----------|-------|
| 118020 | 3  | DHCP lease op (Create / Update / Delete)             | — |
| 118021 | 7  | DHCP lease **Abandon** (conflict / starvation / rogue) | T1498 |
| 118022 | 10 | 10+ abandons on one subnet in 120s — **DHCP starvation** | T1498 |

### Service / pre-staged

| ID     | Level | Fires on |
|--------|-------|----------|
| 118030 | 0  | BloxOne service log (telemetry) |
| 118031 | 5  | Service log WARN / ERROR / FATAL / CRITICAL |
| 118040–118041 | 5 / 10 | _(pre-staged)_ Audit log activity / failed admin action |
| 118050 | 12 | _(pre-staged)_ SOC Insight (server-side Threat Insight) |

---

## Threat-level mapping

`InfobloxThreatLevel` is a **0–100 score**, not a small ordinal. The official
buckets (and how this ruleset maps them) are:

| Score   | Infoblox severity | Wazuh rule | Wazuh level |
|---------|-------------------|------------|-------------|
| 0–29    | Low               | 118010     | 8  |
| 30–79   | Medium            | 118014     | 9  |
| 80–100  | High              | 118011     | 12 |

> ⚠️ A naive `threat_level >= 2` test (treating it as an ordinal) misfires Low
> scores as critical. This ruleset uses anchored numeric ranges instead.

---

## Decoder design

```
infoblox-cef                 (parent — prematch on CEF:0|Infoblox|Data Connector)
├── infoblox-cef-dns-v2      DNS Response — enriched (tags/host/network/conn-type/dst/proto)
├── infoblox-cef-dns         DNS Response (cloud field order) — fallback
├── infoblox-cef-dns-niosx   DNS Response (NIOS-X field order) — fallback
├── infoblox-cef-rpz-v2      RPZ — enriched superset (identity/site/policy/zone/IOC)
├── infoblox-cef-rpz-rich    RPZ + feed name + threat confidence/level/property — fallback
├── infoblox-cef-rpz         RPZ + threat level/property (no feed) — fallback
├── infoblox-cef-rpz-min     RPZ minimal (action/src/domain) — fallback
├── infoblox-cef-dhcp-v2     DHCP lease — enriched (hostname/clientid/lifetime)
├── infoblox-cef-dhcp        DHCP lease — fallback
└── infoblox-cef-service-v2  BloxOne service log — enriched (error text + service id)
```

**Ordering matters.** Wazuh applies the *first* sibling decoder whose regex
matches. The `-v2` decoders are placed **first** and are a strict **superset**
of every field the rules need, plus full context. If a `-v2` regex doesn't match
(e.g. an unexpected field order), decoding falls through to the legacy
rich → full → min decoders, so the rules still fire — enrichment degrades
gracefully and never breaks detection.

### Captured fields

**Core (all event families):** `srcip`, `dns_domain`, `dns_type`,
`dns_response`, `rpz_action`, `rpz_feed`, `threat_confidence`, `threat_level`,
`threat_property`, `dhcp_ip`, `dhcp_mac`, `dhcp_subnet`, `dhcp_leaseop`,
`service_name`.

**Enriched (v2 decoders):**

| Field | Source CEF key | Where | Notes |
|-------|----------------|-------|-------|
| `srcuser` | `suser` | RPZ | User identity — populated on endpoint / `remote_client` events |
| `src_os` | `InfobloxB1SrcOSVersion` | RPZ | Endpoint OS, e.g. `macOS 26.3.1` |
| `hostname` | `dvchost` / `shost` | DNS, RPZ, DHCP | Device hostname (DHCP `shost` = the IP↔host map) |
| `infoblox_network` | `InfobloxB1Network` | DNS, RPZ | Network / site name |
| `infoblox_ophost` | `InfobloxB1OPHName` | DNS, RPZ | DFP / on-prem host (site) |
| `infoblox_conn_type` | `InfobloxB1ConnectionType` | DNS, RPZ | `dfp` / `remote_office` / `remote_client` |
| `infoblox_dns_tags` | `InfobloxB1DNSTags` | DNS, RPZ | App / category classification |
| `dstip` | `dst` | DNS, RPZ | Resolver / sinkhole / redirect target |
| `srcport` | `spt` | DNS, RPZ | Source port |
| `protocol` | `proto` | DNS | UDP / TCP |
| `threat_indicator` | `InfobloxB1ThreatIndicator` | RPZ | The matched IOC |
| `rpz_zone` | `InfobloxRPZ` | RPZ | RPZ zone that fired |
| `rpz_rule` | `InfobloxRPZRule` | RPZ | Full rewrite rule |
| `rpz_policy` | `InfobloxB1PolicyName` | RPZ | Security policy name |
| `rpz_feedtype` | `InfobloxB1FeedType` | RPZ | Feed type (FQDN / IP) |
| `srcmac` | `smac` | RPZ | Client MAC |
| `dhcp_clientid` | `InfobloxClientID` | DHCP | DHCP client identifier |
| `dhcp_lifetime` | `InfobloxLifetime` | DHCP | Lease lifetime (s) |
| `infoblox_msg` | `msg` | Service | The actual service log / error line |
| `infoblox_service_id` | `InfobloxServiceId` | Service | BloxOne service id |

> **Field naming** deliberately reuses Wazuh's existing keyword fields
> (`srcip`, `dstip`, `srcuser`, `srcport`, `protocol`, `hostname`) and prefixes
> Infoblox-specific concepts (`infoblox_*`, `rpz_*`, `dhcp_*`). It avoids
> `data.os`, `data.user` and `data.status`, which are **objects** in the
> `wazuh-alerts` mapping — writing a string there causes a mapping conflict that
> silently drops the document from the index.

### Implementation notes

- **Quoted / empty values.** v2 decoders capture possibly-quoted, space-bearing,
  or empty values with a single PCRE2 branch-reset group:
  `(?|"([^"]*)"|(\S+))?`. Empty values are omitted (no empty-string fields in
  the index) rather than stored as `""`.
- **CEF field order is positional.** The 2.1.3 emitter is stable, but Infoblox
  can change ordering between pipeline versions. If a future version reorders
  keys, the `-v2` regex may stop matching and decoding falls back to the legacy
  decoders (rules keep firing, enrichment is reduced).
- **`suser` (user identity)** is empty on `dfp` / `remote_office` flows and
  populated on `remote_client` / BloxOne Endpoint events; it is captured as
  `srcuser` on RPZ events and omitted when empty. (It is intentionally *not*
  captured on DNS Response events, where it is always empty in practice.)
- IPv6/DUID-only DHCP leases (no `smac`) are not matched by the DHCP decoders.

---

## Installation

### Single node / manager

```bash
# 1. Copy files
cp decoders/112-infoblox-decoders.xml /var/ossec/etc/decoders/
cp rules/112-infoblox-rules.xml       /var/ossec/etc/rules/

# 2. Ownership + permissions (analysisd runs as the 'wazuh' user)
chown wazuh:wazuh /var/ossec/etc/decoders/112-infoblox-decoders.xml \
                  /var/ossec/etc/rules/112-infoblox-rules.xml
chmod 660 /var/ossec/etc/decoders/112-infoblox-decoders.xml
chmod 640 /var/ossec/etc/rules/112-infoblox-rules.xml

# 3. Restart
systemctl restart wazuh-manager
```

> ⚠️ If you edit these files with a tool that runs as `root`, the file may be
> rewritten `root:root` and `wazuh-analysisd` (running as `wazuh`) will fail to
> read it (`ERROR (1226)`). Always re-apply `chown wazuh:wazuh` after editing.

### Cluster

Place the files on the **master** node only. Wazuh's cluster integrity sync
distributes `etc/rules` and `etc/decoders` to all workers automatically. Restart
the master (`systemctl restart wazuh-manager`); workers reload on sync.

---

## Testing

Validate decoding and rule matching with `wazuh-logtest` (writes to stderr):

```bash
# Single event
printf '%s\n' "$(grep -m1 RPZ-QNAME-REDIRECT samples/infoblox-cef-samples.log)" \
  | /var/ossec/bin/wazuh-logtest

# All samples
grep -v '^#' samples/infoblox-cef-samples.log | /var/ossec/bin/wazuh-logtest
```

Expected for the level-80 RPZ sample:

```
**Phase 2: Completed decoding.
        name: 'infoblox-cef'
        rpz_feed: 'Infoblox_High_Risk'
        threat_confidence: '100'
        threat_level: '80'
        threat_property: 'Suspicious_Nameserver'
**Phase 3: Completed filtering (rules).
        id: '118011'
        level: '12'
        description: 'Infoblox RPZ: HIGH threat (level 80) ...'
```

> **Note:** `wazuh-logtest` does **not** simulate `frequency` / `if_matched_sid`
> correlation state, so composite rules (118003, 118005, 118007, 118013, 118022)
> will not fire in logtest. Validate those against live traffic.

---

## Tuning

The correlation thresholds are conservative starting points — tune to your
baseline:

| Rule   | Threshold        | Tune if… |
|--------|------------------|----------|
| 118003 | 20 NXDOMAIN / 60s | Lots of legit NXDOMAIN (search-domain suffixing, k8s) |
| 118005 | 15 SERVFAIL / 60s | Flaky upstreams cause noise |
| 118007 | 40 TXT/NULL / 60s | Mail servers doing SPF/DKIM/DMARC lookups trip it |
| 118022 | 10 abandons / 120s | Constrained pools abandon normally |

---

## Roadmap

- Verify and enable **Audit log** and **SOC Insights** decoders/rules once a
  live sample is available.
- Add detections that leverage the enriched fields: user/host-attributed RPZ
  repeat-offenders (`srcuser` / `hostname`), and category-based rules off
  `infoblox_dns_tags` (DoH, anonymizers, personal storage).
- Add RPZ-IP / RPZ-CLIENT-IP specific handling if those trigger types are
  enabled (the prematch already decodes them; dedicated rules can refine).

---

## License

MIT — see [LICENSE](LICENSE).

Not affiliated with or endorsed by Infoblox or Wazuh. "Infoblox", "BloxOne" and
"NIOS" are trademarks of Infoblox; "Wazuh" is a trademark of Wazuh Inc.

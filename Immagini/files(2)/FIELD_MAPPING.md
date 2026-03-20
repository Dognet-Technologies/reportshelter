# CyberReport Pro — Cross-Tool Field Mapping Table
# Versione: 1.0 | Aggiornato: 2026-03-18
#
# Legenda:
#   DB Field      = nome colonna nel database (canonical name)
#   Type          = tipo Python del valore normalizzato
#   Required      = obbligatorio per creare una Vulnerability/Host
#   Nmap path     = XPath nel file XML Nmap
#   Nikto path    = XPath nel file XML Nikto
#   Burp path     = XPath nel file XML Burp Suite
#   OpenVAS path  = XPath nel file XML OpenVAS/Greenbone
#   Metasploit    = XPath nel file XML Metasploit db_export
#   Nuclei        = JSON key nel file JSON Nuclei
#   CSV/Excel     = nomi colonna comuni (case-insensitive)
#   Notes         = normalizzazione speciale richiesta

## SEZIONE 1: HOST / ASSET

| DB Field            | Type      | Req | Nmap XML Path                              | Nikto XML Path              | Burp XML Path           | OpenVAS XML Path                        | Metasploit XML Path          | Nuclei JSON Key   | CSV/Excel aliases                              | Notes                                      |
|---------------------|-----------|-----|--------------------------------------------|-----------------------------|-------------------------|-----------------------------------------|------------------------------|-------------------|------------------------------------------------|--------------------------------------------|
| ip_address          | str       | YES | address[@addrtype='ipv4']/@addr            | target/@ip                  | host/text()             | asset/host/text()                       | host/@address                | ip                | ip, ip_address, address, host_ip               | Può essere IPv6; normalize_host()          |
| ipv6_address        | str       | NO  | address[@addrtype='ipv6']/@addr            | —                           | —                       | asset/host[@type='ipv6']/text()         | —                            | —                 | ipv6, ipv6_address                             |                                            |
| mac_address         | str       | NO  | address[@addrtype='mac']/@addr             | —                           | —                       | —                                       | host/mac/text()              | —                 | mac, mac_address, mac_addr                     | Uppercase, separatore ':'                  |
| hostname            | str       | NO  | hostnames/hostname[@type='PTR']/@name      | target/@host                | host/text()             | asset/name/text()                       | host/name/text()             | host              | hostname, host, fqdn, server, asset, target    | Strippare "https://", porta, path          |
| host_state          | str       | NO  | status/@state                              | (sempre up)                 | (sempre up)             | (sempre up)                             | host/state/text()            | —                 | state, status                                  | "up"/"down"                                |
| host_reason         | str       | NO  | status/@reason                             | —                           | —                       | —                                       | —                            | —                 | —                                              |                                            |
| scan_start_time     | datetime  | NO  | host/@starttime (unix ts)                  | scandetails/@starttime      | —                       | creation_time/text()                    | —                            | timestamp         | scan_date, date, timestamp                     | parse_unix_ts()                            |
| scan_end_time       | datetime  | NO  | host/@endtime (unix ts)                    | scandetails/@endtime        | —                       | modification_time/text()                | —                            | —                 | —                                              |                                            |

## SEZIONE 2: PORTA / SERVIZIO

| DB Field            | Type      | Req | Nmap XML Path                              | Nikto XML Path              | Burp XML Path           | OpenVAS XML Path                        | Metasploit XML Path          | Nuclei JSON Key   | CSV/Excel aliases                              | Notes                                      |
|---------------------|-----------|-----|--------------------------------------------|-----------------------------|-------------------------|-----------------------------------------|------------------------------|-------------------|------------------------------------------------|--------------------------------------------|
| affected_port       | int       | NO  | port/@portid                               | target/@port                | port/text()             | port/text() → split '/'[0]             | service/port/text()          | port              | port, porta, tcp_port, service_port            | normalize_port(): "443/tcp"→443            |
| affected_protocol   | str       | NO  | port/@protocol                             | (tcp default)               | —                       | port/text() → split '/'[1]             | service/proto/text()         | type              | protocol, proto                                | "tcp"/"udp"                                |
| port_state          | str       | NO  | port/state/@state                          | (open default)              | —                       | —                                       | —                            | —                 | port_state, state                              | "open"/"closed"/"filtered"                 |
| port_reason         | str       | NO  | port/state/@reason                         | —                           | —                       | —                                       | —                            | —                 | —                                              |                                            |
| affected_service    | str       | NO  | port/service/@name                         | (dal nikto banner)          | —                       | nvt/family/text()                       | service/name/text()          | type              | service, protocol, servizio                    |                                            |
| service_product     | str       | NO  | port/service/@product                      | target/@banner              | —                       | —                                       | —                            | —                 | product, software, application                 |                                            |
| service_version     | str       | NO  | port/service/@version                      | —                           | —                       | —                                       | —                            | —                 | version, ver, sw_version                       |                                            |
| service_extra_info  | str       | NO  | port/service/@extrainfo                    | —                           | —                       | —                                       | —                            | —                 | extra_info, banner                             |                                            |
| service_cpe         | str[]     | NO  | port/service/cpe/text()                    | —                           | —                       | nvt/refs/ref[@type='cpe']/@id           | —                            | —                 | cpe                                            | Lista, può essere multipla                 |
| detection_method    | str       | NO  | port/service/@method                       | —                           | —                       | —                                       | —                            | —                 | —                                              | "probed"/"table"                           |
| detection_confidence| int       | NO  | port/service/@conf                         | —                           | —                       | —                                       | —                            | —                 | confidence, conf                               | 0-10                                       |

## SEZIONE 3: VULNERABILITÀ

| DB Field            | Type      | Req | Nmap XML Path                              | Nikto XML Path              | Burp XML Path                    | OpenVAS XML Path                        | Metasploit XML Path          | Nuclei JSON Key         | CSV/Excel aliases                              | Notes                                              |
|---------------------|-----------|-----|--------------------------------------------|-----------------------------|----------------------------------|-----------------------------------------|------------------------------|-------------------------|------------------------------------------------|----------------------------------------------------|
| title               | str       | YES | script/@id + product (sintesi)             | item/description/text()     | name/text()                      | nvt/name/text()                         | vuln/name/text()             | info.name               | title, name, vulnerability, vuln, finding     | normalize_title_for_dedup() per dedup key          |
| description         | text      | NO  | script/@output (parsed)                    | item/description/text()     | issueBackground/text()           | description/text()                      | vuln/info/text()             | info.description        | description, details, detail, note, notes     |                                                    |
| severity            | enum      | YES | derivata da cvss_score / script type       | derivata da OSVDB/cvss      | severity/text()                  | threat/text()                           | derivata da CVSSv2           | info.severity           | severity, risk, criticality, livello, gravità | normalize_severity(): "High"/"high"/"H"/"7.5"→enum |
| cvss_score          | float     | NO  | vulners: elem[@key='cvss']                 | (lookup OSVDB)              | cvssScore/text()                 | severity/text() (è il score diretto)   | refs/ref[@type='CVSSv2']     | info.classification.cvss-score | cvss, cvss_score, score, cvss score     | 0.0-10.0; normalize_cvss()                         |
| cvss_vector         | str       | NO  | —                                          | —                           | cvssVector/text()                | —                                       | —                            | info.classification.cvss-metrics | cvss_vector, cvss vector                 | es. "CVSS:3.1/AV:N/AC:L/..."                      |
| cve_id              | str[]     | NO  | vulners: elem[@key='id'] type=cve          | item/@osvdbid → lookup      | references → CVE-xxxx            | nvt/refs/ref[@type='cve']/@id           | refs/ref[@type='CVE']        | info.classification.cve-id | cve, cve_id, cve id, cve-id              | normalize_cve(): uppercase, valida pattern         |
| cwe_id              | str       | NO  | —                                          | —                           | cweid/text()                     | nvt/refs/ref[@type='cwe']/@id           | —                            | info.classification.cwe-id | cwe, cwe_id                                 |                                                    |
| cpe                 | str       | NO  | port/service/cpe/text() (host CPE)         | —                           | —                                | nvt/refs/ref[@type='cpe']/@id           | —                            | —                       | cpe                                            |                                                    |
| affected_host       | str       | YES | (vedi sezione HOST)                        | target/@host                | host/text()                      | asset/name/text()                       | host/name/text()             | host                    | hostname, host, fqdn, target, asset           |                                                    |
| affected_ip         | str       | YES | address[@addrtype='ipv4']/@addr            | target/@ip                  | (da hostname lookup)             | asset/host/text()                       | host/@address                | ip                      | ip, ip_address                                 |                                                    |
| affected_port       | int       | NO  | (vedi sezione PORTA)                       | target/@port                | port/text()                      | port/text()                             | service/port/text()          | port                    | port, porta                                    |                                                    |
| evidence            | text      | NO  | script/@output (full)                      | item/uri/text()             | requestresponse/request/text()   | detection/result/details/text()         | vuln/proof/text()            | matched-at              | evidence, proof, output, evidenza, request    |                                                    |
| evidence_request    | text      | NO  | —                                          | —                           | requestresponse/request/text()   | —                                       | —                            | curl-command            | request, http_request                          |                                                    |
| evidence_response   | text      | NO  | —                                          | —                           | requestresponse/response/text()  | —                                       | —                            | extracted-results       | response, http_response                        |                                                    |
| remediation         | text      | NO  | —                                          | —                           | remediationBackground/text()     | nvt/solution/text()                     | —                            | info.remediation        | remediation, fix, solution, mitigation, soluzione |                                                 |
| references          | json[]    | NO  | vulners: lista tabelle con id/type/url     | item/@osvdbid               | references/reference/text()      | nvt/refs/ref                            | refs/ref                     | info.reference          | references, refs, url, link                    | Lista di {id, type, url, cvss, is_exploit}         |
| source_tool         | str       | YES | "nmap" (costante)                          | "nikto"                     | "burp"                           | "openvas"                               | "metasploit"                 | "nuclei"                | tool, scanner, source                          | Costante per parser                                |
| source_script       | str       | NO  | script/@id                                 | —                           | type/text()                      | nvt/oid/text()                          | —                            | template-id             | script, plugin, check                          |                                                    |
| raw_output          | text      | NO  | script/@output (raw, con entities)         | item XML completo           | issue XML completo               | result XML completo                     | vuln XML completo            | JSON entry completa     | raw, output, raw_output                        | Archivio per audit, non mostrato in report         |
| is_exploit_available| bool      | NO  | vulners: elem[@key='is_exploit']           | —                           | —                                | —                                       | (presenza refs type=exploit) | —                       | exploit, exploit_available, has_exploit        |                                                    |
| epss_score          | float     | NO  | — (lookup esterno post-import)             | — (lookup)                  | — (lookup)                       | — (lookup)                              | — (lookup)                   | — (lookup)              | epss, epss_score                               | Richiede API NVD/EPSS dopo import                  |

## SEZIONE 4: OS DETECTION (solo Nmap)

| DB Field            | Type      | Req | Nmap XML Path                              | Note                                                                 |
|---------------------|-----------|-----|--------------------------------------------|----------------------------------------------------------------------|
| os_name             | str       | NO  | os/osmatch/@name                           | Best match = osmatch con accuracy più alta                           |
| os_accuracy         | int       | NO  | os/osmatch/@accuracy                       | 0-100                                                                |
| os_type             | str       | NO  | os/osmatch/osclass/@type                   | "general purpose", "webcam", "router"...                             |
| os_vendor           | str       | NO  | os/osmatch/osclass/@vendor                 | "Linux", "Microsoft", "Cisco"...                                     |
| os_family           | str       | NO  | os/osmatch/osclass/@osfamily               | "Linux", "Windows", "IOS"...                                         |
| os_generation       | str       | NO  | os/osmatch/osclass/@osgen                  | "3.X", "10", "2019"...                                               |
| os_cpe              | str[]     | NO  | os/osmatch/osclass/cpe/text()              | Lista CPE per tutti gli osclass del best osmatch                     |

## SEZIONE 5: SCAN METADATA

| DB Field            | Type      | Req | Nmap XML Path                              | Nikto XML Path              | Burp XML Path           | OpenVAS XML Path                        | Nuclei JSON Key         | Note                                           |
|---------------------|-----------|-----|--------------------------------------------|-----------------------------|-------------------------|-----------------------------------------|-------------------------|------------------------------------------------|
| scanner_name        | str       | YES | nmaprun/@scanner                           | "nikto" (costante)          | "burp" (costante)       | "openvas" (costante)                    | "nuclei" (costante)     |                                                |
| scanner_version     | str       | NO  | nmaprun/@version                           | nmaprun/@version            | burpVersion (attribute) | —                                       | —                       |                                                |
| scan_args           | str       | NO  | nmaprun/@args                              | —                           | —                       | —                                       | —                       | Comandi usati per la scansione                 |
| scan_date           | datetime  | NO  | nmaprun/@start (unix ts)                   | scandetails/@starttime      | —                       | creation_time/text()                    | timestamp               |                                                |
| scan_type           | str       | NO  | nmaprun/scaninfo/@type                     | —                           | —                       | —                                       | —                       | "syn", "connect", "udp"...                     |
| hosts_up            | int       | NO  | nmaprun/runstats/hosts/@up                 | —                           | —                       | —                                       | —                       |                                                |
| hosts_down          | int       | NO  | nmaprun/runstats/hosts/@down               | —                           | —                       | —                                       | —                       |                                                |
| scan_duration_sec   | float     | NO  | nmaprun/runstats/finished/@elapsed         | —                           | —                       | —                                       | —                       |                                                |

---
## NOTE IMPLEMENTATIVE

### normalize_severity() — tabella di conversione
| Input                          | Output   |
|--------------------------------|----------|
| critical, CRITICAL, critico    | Critical |
| high, HIGH, alto, H            | High     |
| medium, MEDIUM, medio, M, moderate | Medium|
| low, LOW, basso, L             | Low      |
| info, INFO, informational, I   | Info     |
| 9.0 - 10.0 (CVSS)             | Critical |
| 7.0 - 8.9  (CVSS)             | High     |
| 4.0 - 6.9  (CVSS)             | Medium   |
| 0.1 - 3.9  (CVSS)             | Low      |
| 0.0        (CVSS)             | Info     |
| 5 (scala 1-5)                  | Critical |
| 4 (scala 1-5)                  | High     |
| 3 (scala 1-5)                  | Medium   |
| 2 (scala 1-5)                  | Low      |
| 1 (scala 1-5)                  | Info     |

### dedup_key() — logica
Chiave = SHA256(title_normalized | host | port)[:16]
- title_normalized = lowercase, rimuovi numeri versione, strip path specifici
- Due vuln da tool diversi con stesso (title_norm + host + port) → stesso record, sources uniti
- I CVE identici su host diversi NON sono duplicati

# CyberReport Pro — Parser Module
## Struttura
```
cyberreport_pro_parsers/
├── CLAUDE.md                  # Spec completa per Claude Code
├── parsers/
│   ├── canonical_schema.py    # Schema canonico condiviso (LEGGERE PRIMA DI TUTTO)
│   ├── nvd_enricher.py        # NVD API v2 enricher (Celery task)
│   ├── nmap_parser.py         # Nmap XML parser (71 test)
│   ├── burp_parser.py         # Burp Suite XML parser (48 test)
│   └── openvas_parser.py      # OpenVAS XML+CSV + Nessus CSV parser (34 test)
├── tests/
│   ├── test_nmap_parser.py
│   ├── test_burp_parser.py
│   └── test_openvas_parser.py
└── docs/
    ├── SESSION_DECISIONS.md   # Tutte le decisioni architetturali di sessione
    └── FIELD_MAPPING.md       # Tabella cross-tool: campo DB → XPath/JSON per ogni tool
```

## Quick Start
```bash
pip install pytest nvdlib openpyxl

# Test tutti i parser
cd tests/
pytest test_nmap_parser.py test_burp_parser.py test_openvas_parser.py -v

# Uso manuale
from parsers.openvas_parser import detect_and_parse
result = detect_and_parse('my_scan.xml')
print(result.stats)
```

## Parser supportati
| Parser | Formati | Test |
|---|---|---|
| Nmap | XML (-oX) | 71/71 |
| Burp Suite | XML (v1.0/v1.1, base64) | 48/48 |
| OpenVAS/Greenbone | XML (GMP), CSV | 34/34 |
| Nessus | CSV | Incluso in openvas_parser.py |

## Prossimi parser da implementare
- Nikto XML
- Nuclei JSON
- Metasploit XML (db_export)
- CSV generico con template fingerprinting

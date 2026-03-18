"""
CyberReport Pro — NVD Enricher
==============================
Arricchisce le NormalizedVulnerability con dati NVD API v2.

Flusso:
  1. Parser salva vuln con nvd_enrichment_status=PENDING e cve_ids_tool popolato
  2. Task Celery chiama NvdEnricher.enrich_bulk(cve_ids)
  3. NvdEnricher chiama NVD API v2 con rate limiting
  4. Mappa la risposta NVD → NvdEnrichmentData
  5. Chiama apply_nvd_enrichment(vuln, data) per popolare i campi Sezione B
  6. Aggiorna nvd_enrichment_status → DONE / FAILED / PARTIAL

Rate limits NVD API v2:
  - Senza API key: 5 req / 30s rolling window → delay 6s tra richieste
  - Con API key:  50 req / 30s rolling window → delay 0.6s tra richieste

Dipendenze:
  pip install nvdlib>=0.7.6

Author: CyberReport Pro
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Optional

from cyberreport_pro_parsers.parsers.canonical_schema import (
    CisaKevData,
    CvssV2Data,
    CvssV3Data,
    EnrichmentStatus,
    NormalizedVulnerability,
    NvdCpeMatch,
    NvdEnrichmentData,
    NvdReference,
    NvdWeakness,
    Severity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mapper: risposta nvdlib → NvdEnrichmentData
# ---------------------------------------------------------------------------

class NvdResponseMapper:
    """
    Mappa un oggetto CVE restituito da nvdlib verso NvdEnrichmentData.

    nvdlib restituisce oggetti con attributi dinamici — usiamo getattr
    con fallback per gestire CVE antichi con dati mancanti (pre-2016).

    Mappatura completa NVD API v2 → campi canonici:

    NVD API v2 JSON path                          → NvdEnrichmentData field
    ─────────────────────────────────────────────────────────────────────
    cve.id                                         → cve_id
    cve.published                                  → published
    cve.lastModified                               → last_modified
    cve.vulnStatus                                 → vuln_status
    cve.descriptions[lang='en'].value              → description_en
    cve.metrics.cvssMetricV31[0].cvssData.*        → cvss_v31 (CvssV3Data)
    cve.metrics.cvssMetricV30[0].cvssData.*        → cvss_v30 (CvssV3Data)
    cve.metrics.cvssMetricV2[0].cvssData.*         → cvss_v2  (CvssV2Data)
    cve.weaknesses[N].description[lang='en'].value → weaknesses (NvdWeakness)
    cve.references[N].url / .source / .tags        → references (NvdReference)
    cve.configurations[N].nodes[M].cpeMatch[K].*   → cpe_matches (NvdCpeMatch)
    cve.cisaExploitAdd                             → kev.exploit_add
    cve.cisaActionDue                              → kev.action_due
    cve.cisaRequiredAction                         → kev.required_action
    cve.cisaVulnerabilityName                      → kev.vulnerability_name
    """

    def map(self, cve_obj) -> NvdEnrichmentData:
        """Converte un oggetto nvdlib CVE in NvdEnrichmentData."""
        data = NvdEnrichmentData()

        data.cve_id      = getattr(cve_obj, 'id', '') or ''
        data.vuln_status = getattr(cve_obj, 'vulnStatus', '') or ''
        data.published   = self._parse_dt(getattr(cve_obj, 'published', None))
        data.last_modified = self._parse_dt(getattr(cve_obj, 'lastModified', None))

        data.description_en = self._extract_description(cve_obj)
        data.cvss_v31       = self._extract_cvss_v3(cve_obj, 'cvssMetricV31', '3.1')
        data.cvss_v30       = self._extract_cvss_v3(cve_obj, 'cvssMetricV30', '3.0')
        data.cvss_v2        = self._extract_cvss_v2(cve_obj)
        data.weaknesses     = self._extract_weaknesses(cve_obj)
        data.references     = self._extract_references(cve_obj)
        data.cpe_matches    = self._extract_cpe_matches(cve_obj)
        data.kev            = self._extract_kev(cve_obj)

        return data

    # --- Descrizione ---

    def _extract_description(self, cve_obj) -> str:
        """
        Estrae la descrizione EN dalla lista descriptions.
        Path NVD: cve.descriptions[lang='en'].value
        nvdlib attr: cve_obj.descriptions (list di oggetti con .lang e .value)
        """
        descriptions = getattr(cve_obj, 'descriptions', []) or []
        for desc in descriptions:
            if getattr(desc, 'lang', '') == 'en':
                return getattr(desc, 'value', '') or ''
        # fallback: primo elemento qualsiasi
        if descriptions:
            return getattr(descriptions[0], 'value', '') or ''
        return ''

    # --- CVSS v3 ---

    def _extract_cvss_v3(self, cve_obj, attr_name: str, version: str) -> Optional[CvssV3Data]:
        """
        Estrae dati CVSS v3.x.
        nvdlib attr: cve_obj.metrics.cvssMetricV31 oppure cvssMetricV30
        Ogni entry ha: .cvssData (con tutti i campi) e .exploitabilityScore / .impactScore
        """
        metrics = getattr(cve_obj, 'metrics', None)
        if not metrics:
            return None

        entries = getattr(metrics, attr_name, None) or []
        if not entries:
            return None

        # Preferisci source_type "Primary" (NVD ufficiale) su "Secondary" (CNA)
        entry = next(
            (e for e in entries if getattr(e, 'type', '') == 'Primary'),
            entries[0]
        )

        cvss_data = getattr(entry, 'cvssData', None)
        if not cvss_data:
            return None

        result = CvssV3Data(version=version)

        # Score e severity
        result.base_score    = self._safe_float(getattr(cvss_data, 'baseScore', None))
        result.base_severity = getattr(cvss_data, 'baseSeverity', '') or ''
        result.vector_string = getattr(cvss_data, 'vectorString', '') or ''

        # Vettori individuali
        result.attack_vector          = getattr(cvss_data, 'attackVector', '') or ''
        result.attack_complexity      = getattr(cvss_data, 'attackComplexity', '') or ''
        result.privileges_required    = getattr(cvss_data, 'privilegesRequired', '') or ''
        result.user_interaction       = getattr(cvss_data, 'userInteraction', '') or ''
        result.scope                  = getattr(cvss_data, 'scope', '') or ''
        result.confidentiality_impact = getattr(cvss_data, 'confidentialityImpact', '') or ''
        result.integrity_impact       = getattr(cvss_data, 'integrityImpact', '') or ''
        result.availability_impact    = getattr(cvss_data, 'availabilityImpact', '') or ''

        # Sub-scores
        result.exploitability_score = self._safe_float(getattr(entry, 'exploitabilityScore', None))
        result.impact_score         = self._safe_float(getattr(entry, 'impactScore', None))

        # Fonte
        result.source      = getattr(entry, 'source', '') or ''
        result.source_type = getattr(entry, 'type', '') or ''

        return result

    # --- CVSS v2 ---

    def _extract_cvss_v2(self, cve_obj) -> Optional[CvssV2Data]:
        """
        Estrae dati CVSS v2.0 (solo per CVE storici pre-2016).
        nvdlib attr: cve_obj.metrics.cvssMetricV2
        """
        metrics = getattr(cve_obj, 'metrics', None)
        if not metrics:
            return None

        entries = getattr(metrics, 'cvssMetricV2', None) or []
        if not entries:
            return None

        entry     = entries[0]
        cvss_data = getattr(entry, 'cvssData', None)
        if not cvss_data:
            return None

        result = CvssV2Data()
        result.base_score    = self._safe_float(getattr(cvss_data, 'baseScore', None))
        result.vector_string = getattr(cvss_data, 'vectorString', '') or ''
        result.base_severity = getattr(entry, 'baseSeverity', '') or ''

        result.access_vector        = getattr(cvss_data, 'accessVector', '') or ''
        result.access_complexity    = getattr(cvss_data, 'accessComplexity', '') or ''
        result.authentication       = getattr(cvss_data, 'authentication', '') or ''
        result.confidentiality_impact = getattr(cvss_data, 'confidentialityImpact', '') or ''
        result.integrity_impact     = getattr(cvss_data, 'integrityImpact', '') or ''
        result.availability_impact  = getattr(cvss_data, 'availabilityImpact', '') or ''

        result.exploitability_score = self._safe_float(getattr(entry, 'exploitabilityScore', None))
        result.impact_score         = self._safe_float(getattr(entry, 'impactScore', None))

        return result

    # --- Weaknesses (CWE) ---

    def _extract_weaknesses(self, cve_obj) -> list[NvdWeakness]:
        """
        Estrae lista CWE.
        nvdlib attr: cve_obj.weaknesses (list con .source, .type, .description)
        Ogni entry .description è lista di {lang, value} — vogliamo lang='en'.
        """
        result: list[NvdWeakness] = []
        weaknesses = getattr(cve_obj, 'weaknesses', []) or []

        for w in weaknesses:
            source        = getattr(w, 'source', '') or ''
            weakness_type = getattr(w, 'type', '') or ''
            descriptions  = getattr(w, 'description', []) or []

            for desc in descriptions:
                if getattr(desc, 'lang', '') != 'en':
                    continue
                cwe_value = getattr(desc, 'value', '') or ''
                # Filtra "NVD-CWE-Other" e "NVD-CWE-noinfo" — non sono CWE reali
                if not cwe_value.startswith('CWE-') or 'noinfo' in cwe_value or 'Other' in cwe_value:
                    continue
                result.append(NvdWeakness(
                    cwe_id       = cwe_value,
                    source       = source,
                    weakness_type = weakness_type,
                ))

        return result

    # --- References ---

    def _extract_references(self, cve_obj) -> list[NvdReference]:
        """
        Estrae lista reference.
        nvdlib attr: cve_obj.references (list con .url, .source, .tags)
        """
        result: list[NvdReference] = []
        references = getattr(cve_obj, 'references', []) or []

        for ref in references:
            url    = getattr(ref, 'url', '') or ''
            source = getattr(ref, 'source', '') or ''
            tags   = getattr(ref, 'tags', []) or []
            if url:
                result.append(NvdReference(url=url, source=source, tags=list(tags)))

        return result

    # --- CPE Matches ---

    def _extract_cpe_matches(self, cve_obj) -> list[NvdCpeMatch]:
        """
        Estrae configurazioni CPE affected.
        nvdlib attr: cve_obj.configurations (list di nodi con .cpeMatch)
        """
        result: list[NvdCpeMatch] = []
        configurations = getattr(cve_obj, 'configurations', []) or []

        for config in configurations:
            nodes = getattr(config, 'nodes', []) or []
            for node in nodes:
                cpe_matches = getattr(node, 'cpeMatch', []) or []
                for cpe in cpe_matches:
                    result.append(NvdCpeMatch(
                        criteria                = getattr(cpe, 'criteria', '') or '',
                        match_criteria_id       = getattr(cpe, 'matchCriteriaId', '') or '',
                        vulnerable              = getattr(cpe, 'vulnerable', True),
                        version_start_including = getattr(cpe, 'versionStartIncluding', None),
                        version_start_excluding = getattr(cpe, 'versionStartExcluding', None),
                        version_end_including   = getattr(cpe, 'versionEndIncluding', None),
                        version_end_excluding   = getattr(cpe, 'versionEndExcluding', None),
                    ))

        return result

    # --- CISA KEV ---

    def _extract_kev(self, cve_obj) -> Optional[CisaKevData]:
        """
        Estrae dati CISA KEV se presenti.
        nvdlib attr: cve_obj.cisaExploitAdd / cisaActionDue / cisaRequiredAction
        Questi attributi sono presenti SOLO se il CVE è nel catalogo KEV.
        """
        exploit_add = getattr(cve_obj, 'cisaExploitAdd', None)
        if not exploit_add:
            return None

        return CisaKevData(
            exploit_add      = self._parse_dt(exploit_add),
            action_due       = self._parse_dt(getattr(cve_obj, 'cisaActionDue', None)),
            required_action  = getattr(cve_obj, 'cisaRequiredAction', '') or '',
            vulnerability_name = getattr(cve_obj, 'cisaVulnerabilityName', '') or '',
        )

    # --- Utilities ---

    @staticmethod
    def _safe_float(value) -> Optional[float]:
        if value is None:
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_dt(value) -> Optional[datetime]:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
                try:
                    return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return None


# ---------------------------------------------------------------------------
# Applicatore: NvdEnrichmentData → NormalizedVulnerability (Sezione B)
# ---------------------------------------------------------------------------

def apply_nvd_enrichment(
    vuln: NormalizedVulnerability,
    data: NvdEnrichmentData,
) -> None:
    """
    Popola i campi Sezione B di NormalizedVulnerability dai dati NVD.

    REGOLA: questa funzione è l'UNICO punto in cui i campi Sezione B
    vengono scritti. Nessun parser deve chiamarla o replicarne la logica.

    Mapping completo NvdEnrichmentData → NormalizedVulnerability fields:

    NvdEnrichmentData field          → NormalizedVulnerability field
    ─────────────────────────────────────────────────────────────────
    data (intero oggetto)            → nvd_data
    description_en                   → description_nvd
    best_cvss.base_score             → cvss_score
    best_cvss.base_severity          → severity (via Severity.from_string)
    best_cvss.vector_string          → cvss_vector
    best_cvss.version                → cvss_version
    best_cvss.attack_vector          → cvss_av
    best_cvss.attack_complexity      → cvss_ac
    best_cvss.privileges_required    → cvss_pr
    best_cvss.user_interaction       → cvss_ui
    best_cvss.scope                  → cvss_scope
    best_cvss.confidentiality_impact → cvss_c
    best_cvss.integrity_impact       → cvss_i
    best_cvss.availability_impact    → cvss_a
    best_cvss.exploitability_score   → cvss_exploitability_score
    best_cvss.impact_score           → cvss_impact_score
    primary_cwe                      → cwe_id
    [w.cwe_id for w in weaknesses]   → cwe_ids
    published                        → cve_published
    last_modified                    → cve_last_modified
    vuln_status                      → cve_status
    [{url,source,tags}]              → references_nvd
    [c.criteria for c in cpe_matches if c.vulnerable] → cpe_affected
    kev is not None                  → is_kev
    kev.exploit_add                  → kev_date_added
    kev.action_due                   → kev_action_due
    kev.required_action              → kev_required_action
    has_exploit_reference            → is_exploit_available_nvd
    """
    # Salva l'oggetto completo per serializzazione JSON
    vuln.nvd_data = data

    # Descrizione ufficiale
    if data.description_en:
        vuln.description_nvd = data.description_en

    # CVSS — priorità v3.1 > v3.0 > v2
    best = data.best_cvss
    if best:
        vuln.cvss_score    = best.base_score
        vuln.cvss_vector   = best.vector_string
        vuln.cvss_version  = best.version
        vuln.cvss_av       = best.attack_vector
        vuln.cvss_ac       = best.attack_complexity
        vuln.cvss_pr       = best.privileges_required
        vuln.cvss_ui       = best.user_interaction
        vuln.cvss_scope    = best.scope
        vuln.cvss_c        = best.confidentiality_impact
        vuln.cvss_i        = best.integrity_impact
        vuln.cvss_a        = best.availability_impact
        vuln.cvss_exploitability_score = best.exploitability_score
        vuln.cvss_impact_score         = best.impact_score
        # Severity autoritativa da NVD
        if best.base_score is not None:
            vuln.severity = Severity.from_cvss(best.base_score)
        elif best.base_severity:
            vuln.severity = Severity.from_string(best.base_severity)
    elif data.cvss_v2 and data.cvss_v2.base_score is not None:
        # Fallback CVSS v2 per CVE storici
        vuln.cvss_score   = data.cvss_v2.base_score
        vuln.cvss_vector  = data.cvss_v2.vector_string
        vuln.cvss_version = "2.0"
        vuln.severity     = Severity.from_cvss(data.cvss_v2.base_score)

    # CWE
    primary_cwe = data.primary_cwe
    if primary_cwe:
        vuln.cwe_id  = primary_cwe
    vuln.cwe_ids = [w.cwe_id for w in data.weaknesses if w.cwe_id]

    # Date CVE
    vuln.cve_published    = data.published
    vuln.cve_last_modified = data.last_modified
    vuln.cve_status       = data.vuln_status

    # References NVD
    vuln.references_nvd = [
        {"url": r.url, "source": r.source, "tags": r.tags}
        for r in data.references
    ]

    # CPE affected (solo quelli vulnerabili)
    vuln.cpe_affected = [
        c.criteria for c in data.cpe_matches
        if c.vulnerable and c.criteria
    ]

    # CISA KEV
    if data.kev:
        vuln.is_kev             = True
        vuln.kev_date_added     = data.kev.exploit_add
        vuln.kev_action_due     = data.kev.action_due
        vuln.kev_required_action = data.kev.required_action

    # Exploit da NVD references
    vuln.is_exploit_available_nvd = data.has_exploit_reference

    # Stato enrichment
    vuln.nvd_enriched_at = datetime.now(tz=timezone.utc)

    # Determina se enrichment è completo o parziale
    if vuln.cvss_score is not None:
        vuln.nvd_enrichment_status = EnrichmentStatus.DONE
    else:
        # CVE trovato ma senza CVSS (es. CVE molto vecchi o Awaiting Analysis)
        vuln.nvd_enrichment_status = EnrichmentStatus.PARTIAL
        logger.warning("CVE %s trovato in NVD ma senza CVSS score (status: %s)",
                       data.cve_id, data.vuln_status)


# ---------------------------------------------------------------------------
# NVD Enricher — orchestratore principale
# ---------------------------------------------------------------------------

class NvdEnricher:
    """
    Orchestratore per l'enrichment NVD di un batch di CVE ID.

    Uso (da Celery task):
        enricher = NvdEnricher(api_key=settings.NVD_API_KEY)
        results = enricher.enrich_bulk(["CVE-2021-44228", "CVE-2014-0160"])

    Rate limiting:
        nvdlib gestisce internamente il delay tra richieste.
        Il parametro delay è in secondi:
          - Senza API key: 6.0s (5 req/30s)
          - Con API key:   0.6s (50 req/30s)
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.delay   = 0.6 if api_key else 6.0
        self.mapper  = NvdResponseMapper()

        try:
            import nvdlib as _nvdlib
            self._nvdlib = _nvdlib
        except ImportError:
            raise ImportError(
                "nvdlib non installato. Eseguire: pip install nvdlib>=0.7.6"
            )

    def enrich_single(self, cve_id: str) -> Optional[NvdEnrichmentData]:
        """
        Arricchisce un singolo CVE ID.
        Ritorna NvdEnrichmentData oppure None se non trovato.
        """
        try:
            results = self._nvdlib.searchCVE(
                cveId=cve_id,
                key=self.api_key,
                delay=self.delay,
            )
            if not results:
                logger.warning("CVE %s non trovato in NVD", cve_id)
                return None
            return self.mapper.map(results[0])
        except Exception as e:
            logger.error("Errore NVD enrichment per %s: %s", cve_id, e)
            return None

    def enrich_bulk(
        self,
        cve_ids: list[str],
        on_progress: Optional[callable] = None,
    ) -> dict[str, Optional[NvdEnrichmentData]]:
        """
        Arricchisce un batch di CVE ID.

        Ritorna: dict {cve_id: NvdEnrichmentData | None}
          - None = CVE non trovato in NVD o errore

        on_progress: callback(current, total, cve_id) per aggiornamento UI
        """
        results: dict[str, Optional[NvdEnrichmentData]] = {}
        unique_ids = list(dict.fromkeys(cve_ids))  # dedup mantenendo ordine
        total = len(unique_ids)

        for i, cve_id in enumerate(unique_ids):
            if on_progress:
                on_progress(i + 1, total, cve_id)

            data = self.enrich_single(cve_id)
            results[cve_id] = data

            # Rate limiting esplicito tra richieste consecutive
            # (nvdlib lo gestisce internamente con delay, ma aggiungiamo
            # un buffer per evitare 429 su burst)
            if i < total - 1:
                time.sleep(self.delay)

        logger.info(
            "NVD enrichment completato: %d/%d CVE trovati",
            sum(1 for v in results.values() if v is not None),
            total,
        )
        return results

    def apply_to_vulnerabilities(
        self,
        vulnerabilities: list[NormalizedVulnerability],
        on_progress: Optional[callable] = None,
    ) -> dict[str, int]:
        """
        Pipeline completa: dato un batch di NormalizedVulnerability,
        arricchisce quelle che ne hanno bisogno e aggiorna i campi Sezione B.

        Ritorna: statistiche {done, partial, failed, skipped}
        """
        stats = {"done": 0, "partial": 0, "failed": 0, "skipped": 0}

        # Raccogli tutti i CVE ID unici che necessitano enrichment
        to_enrich: dict[str, list[NormalizedVulnerability]] = {}
        for vuln in vulnerabilities:
            if not vuln.needs_nvd_enrichment:
                vuln.nvd_enrichment_status = EnrichmentStatus.SKIPPED
                stats["skipped"] += 1
                continue
            for cve_id in vuln.cve_ids_tool:
                to_enrich.setdefault(cve_id, []).append(vuln)

        if not to_enrich:
            return stats

        # Fetch NVD in bulk
        nvd_results = self.enrich_bulk(list(to_enrich.keys()), on_progress)

        # Applica i risultati
        for cve_id, nvd_data in nvd_results.items():
            for vuln in to_enrich[cve_id]:
                if nvd_data is None:
                    vuln.nvd_enrichment_status = EnrichmentStatus.FAILED
                    # Fallback: usa severity_tool se disponibile
                    if vuln.severity is None and vuln.severity_tool is not None:
                        vuln.severity = vuln.severity_tool
                    stats["failed"] += 1
                else:
                    apply_nvd_enrichment(vuln, nvd_data)
                    if vuln.nvd_enrichment_status == EnrichmentStatus.DONE:
                        stats["done"] += 1
                    else:
                        stats["partial"] += 1

        return stats

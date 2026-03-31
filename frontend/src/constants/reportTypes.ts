/**
 * Shared constants for report types, sections, and chart definitions.
 * Used by SubProjectPage (config toolbar) and ReportBuilderPage.
 */
import type { RiskLevel } from "@/api/types";

// ─── Report Types ─────────────────────────────────────────────────────────────

export type ReportTypeId =
  | "pentest" | "va" | "red_team" | "web_app" | "mobile_app"
  | "cloud" | "network" | "social_eng" | "incident" | "threat_intel"
  | "compliance" | "osint" | "executive"
  | "it_infra" | "code_review" | "arch_review" | "dr" | "it_audit"
  | "remediation" | "retest" | "risk_register" | "patch_mgmt"
  | "breach" | "forensic" | "malware" | "lessons_learned";

export interface ReportTypeInfo {
  id: ReportTypeId;
  label: string;
  desc: string;
  audience: string[];
  category: string;
  /** Does this report type include vulnerability findings? */
  hasVulns: boolean;
}

export const REPORT_TYPES: ReportTypeInfo[] = [
  // Cybersecurity
  { id: "pentest",      label: "Penetration Test Report",       desc: "Black/grey/white box pentest results",           audience: ["executive","management","technical"], category: "Cybersecurity", hasVulns: true  },
  { id: "va",           label: "Vulnerability Assessment",       desc: "Systematic scan without exploitation",           audience: ["management","technical"],             category: "Cybersecurity", hasVulns: true  },
  { id: "red_team",     label: "Red Team Report",                desc: "APT simulation with attack narrative",           audience: ["executive","management","technical"], category: "Cybersecurity", hasVulns: true  },
  { id: "web_app",      label: "Web Application Security",       desc: "OWASP Top 10, DAST/SAST findings",              audience: ["technical","management"],             category: "Cybersecurity", hasVulns: true  },
  { id: "mobile_app",   label: "Mobile Application Security",    desc: "iOS/Android, OWASP MASVS",                      audience: ["technical","management"],             category: "Cybersecurity", hasVulns: true  },
  { id: "cloud",        label: "Cloud Security Assessment",      desc: "AWS/Azure/GCP misconfig, IAM, exposure",         audience: ["technical","management"],             category: "Cybersecurity", hasVulns: true  },
  { id: "network",      label: "Network Security Assessment",    desc: "Segmentation, firewall rules, exposure",         audience: ["technical","management"],             category: "Cybersecurity", hasVulns: true  },
  { id: "social_eng",   label: "Social Engineering Report",      desc: "Phishing/vishing campaigns, results",           audience: ["executive","management"],             category: "Cybersecurity", hasVulns: false },
  { id: "incident",     label: "Incident Response Report",       desc: "Post-incident: timeline, IoC, containment",     audience: ["executive","management","technical"], category: "Cybersecurity", hasVulns: false },
  { id: "threat_intel", label: "Threat Intelligence Report",     desc: "TTPs, threat actors, emerging vulns",           audience: ["management","technical"],             category: "Cybersecurity", hasVulns: false },
  { id: "compliance",   label: "Compliance Gap Assessment",      desc: "ISO 27001, NIS2, GDPR, PCI-DSS, DORA",         audience: ["executive","management"],             category: "Cybersecurity", hasVulns: true  },
  { id: "osint",        label: "OSINT Report",                   desc: "Public exposure, digital footprint",            audience: ["management","technical"],             category: "Cybersecurity", hasVulns: false },
  { id: "executive",    label: "Executive Summary",              desc: "Non-technical synthesis for board/management",  audience: ["executive"],                          category: "Cybersecurity", hasVulns: false },
  // IT General
  { id: "it_infra",     label: "IT Infrastructure Assessment",   desc: "General infrastructure status",                 audience: ["management","technical"],             category: "IT General",    hasVulns: true  },
  { id: "code_review",  label: "Code Review Report",             desc: "Static code analysis findings",                 audience: ["technical"],                          category: "IT General",    hasVulns: true  },
  { id: "arch_review",  label: "Architecture Review",            desc: "Architectural evaluation",                      audience: ["technical","management"],             category: "IT General",    hasVulns: false },
  { id: "dr",           label: "Disaster Recovery Assessment",   desc: "RTO/RPO, backup, continuity",                  audience: ["management","technical"],             category: "IT General",    hasVulns: false },
  { id: "it_audit",     label: "IT Audit",                       desc: "Compliance with procedures, asset inventory",   audience: ["management"],                         category: "IT General",    hasVulns: false },
  // Remediation
  { id: "remediation",  label: "Remediation Plan",               desc: "Prioritized remediation plan with owners",      audience: ["management","technical"],             category: "Remediation",   hasVulns: true  },
  { id: "retest",       label: "Retest / Verification Report",   desc: "Verify fixes from previous assessment",         audience: ["management","technical"],             category: "Remediation",   hasVulns: true  },
  { id: "risk_register",label: "Risk Register",                  desc: "Risk catalog with risk acceptance",             audience: ["executive","management"],             category: "Remediation",   hasVulns: false },
  { id: "patch_mgmt",   label: "Patch Management Report",        desc: "Update status, pending CVEs",                   audience: ["management","technical"],             category: "Remediation",   hasVulns: true  },
  // Breach & Incident
  { id: "breach",        label: "Breach Notification Report",    desc: "For authorities (GDPR Art. 33/34), clients",   audience: ["executive","management"],             category: "Breach & Incident", hasVulns: false },
  { id: "forensic",      label: "Forensic Investigation Report", desc: "Forensic analysis, chain of custody",           audience: ["technical","management"],             category: "Breach & Incident", hasVulns: false },
  { id: "malware",       label: "Malware Analysis Report",       desc: "Sample analysis, IOC, behavior",                audience: ["technical"],                          category: "Breach & Incident", hasVulns: false },
  { id: "lessons_learned",label:"Post-Incident Lessons Learned", desc: "RCA, process improvements",                    audience: ["executive","management"],             category: "Breach & Incident", hasVulns: false },
];

// ─── Report Sections ──────────────────────────────────────────────────────────

export interface ReportSection {
  id: string;
  /** UI label shown in the section list */
  label: string;
  icon: string;
  /** Short description shown below the label */
  desc: string;
  /** The <h2> heading as it appears in the generated document */
  reportTitle: string;
  /** Example / writing-guide text in English — shown in the inline editor */
  example: string;
  required: boolean;
  defaultFor: ReportTypeId[] | "all";
}

export const REPORT_SECTIONS: ReportSection[] = [
  {
    id: "cover", label: "Cover Page", icon: "📄", required: true, defaultFor: "all",
    reportTitle: "Cover Page",
    desc: "Title, client name, date, version and classification — auto-generated from project metadata.",
    example: "",
  },
  {
    id: "toc", label: "Table of Contents", icon: "📋", required: false,
    defaultFor: ["pentest","va","red_team","web_app","mobile_app","cloud","network","compliance","forensic","it_infra"],
    reportTitle: "Table of Contents",
    desc: "Auto-generated list of all enabled sections with page numbers.",
    example: "",
  },
  {
    id: "doc_control", label: "Document Control", icon: "📋", required: false,
    defaultFor: ["pentest","va","red_team","web_app","mobile_app","cloud","network","compliance","it_infra","code_review","arch_review","osint","incident","forensic","malware","breach","lessons_learned"],
    reportTitle: "Document Control",
    desc: "Document version history, classification, authors and distribution list.",
    example: "This document is classified CONFIDENTIAL and is intended solely for the use of authorised personnel. Any reproduction or distribution without prior written consent of the issuing organisation is strictly prohibited.\n\nFor questions regarding this report, contact the lead assessor listed above.",
  },
  {
    id: "executive_summary", label: "Executive Summary", icon: "📊", required: false,
    defaultFor: ["pentest","va","red_team","web_app","cloud","network","executive","retest","compliance","it_infra"],
    reportTitle: "Executive Summary",
    desc: "High-level overview for decision-makers: overall risk posture, KPIs, and key findings at a glance.",
    example: "This report presents the results of the security assessment conducted on behalf of [Client Name] between [Start Date] and [End Date]. The assessment identified [N] vulnerabilities across the in-scope systems, of which [N] are rated Critical or High severity.\n\nThe overall security posture is assessed as [Poor / Fair / Good]. Immediate attention is required for the findings listed in the Remediation Plan section. A follow-up retest is recommended within [30/60/90] days.",
  },
  {
    id: "findings_summary", label: "Findings Summary", icon: "📊", required: false,
    defaultFor: ["va","pentest","red_team","web_app","mobile_app","cloud","network","compliance","it_infra","code_review","risk_register","it_audit","dr"],
    reportTitle: "Findings Summary",
    desc: "Severity distribution charts and a consolidated table of all findings.",
    example: "A total of [N] vulnerabilities were identified during this assessment. The distribution by severity is as follows: [N] Critical, [N] High, [N] Medium, [N] Low, [N] Informational.\n\nThe majority of findings are concentrated in [area/component], suggesting systemic issues with [input validation / patch management / access control]. Priority should be given to the Critical and High severity items detailed in the following sections.",
  },
  {
    id: "engagement_overview", label: "Engagement Overview", icon: "🗂️", required: false,
    defaultFor: ["red_team"],
    reportTitle: "Engagement Overview",
    desc: "Objectives, rules of engagement, assessment team composition and project timeline.",
    example: "The engagement was conducted under the Rules of Engagement (RoE) agreed upon during the kick-off meeting on [Date]. The assessment team operated under [full knowledge / limited knowledge / zero knowledge] of the target environment.\n\nObjectives: (1) Gain initial foothold via external attack surface; (2) Demonstrate impact through lateral movement; (3) Reach the defined Crown Jewel objective.\n\nOut-of-scope systems and prohibited techniques are listed in the RoE document appended to this report.",
  },
  {
    id: "scope", label: "Scope & Methodology", icon: "🎯", required: false,
    defaultFor: ["pentest","va","red_team","web_app","mobile_app","cloud","network","it_infra","code_review"],
    reportTitle: "Scope & Methodology",
    desc: "In-scope assets, IP ranges, application URLs, testing period, and methodology framework applied.",
    example: "The scope of this assessment encompassed the systems and services as defined in the Statement of Work. Testing was conducted between [Start Date] and [End Date] from [External / Internal] network perspective.\n\nIn-scope assets included: [list IP ranges, URLs, application names]. The following systems were explicitly excluded from testing: [list if any].\n\nThe assessment followed the [PTES / OWASP Testing Guide / NIST SP 800-115] methodology, augmented with proprietary techniques developed by [Assessor Org].",
  },
  {
    id: "risk_summary", label: "Risk Summary", icon: "⚠️", required: false,
    defaultFor: ["risk_register","it_audit","dr","arch_review","social_eng"],
    reportTitle: "Risk Summary",
    desc: "Severity distribution charts, overall risk gauge, and risk matrix — use this instead of Executive Summary when a narrative overview is not needed.",
    example: "The overall risk level of the assessed environment is [CRITICAL / HIGH / MEDIUM / LOW]. The distribution of findings reflects a concentration of vulnerabilities in [category/area], which poses a significant risk to [confidentiality / integrity / availability] of [asset type].\n\nKey risk drivers include: [unpatched systems / exposed management interfaces / insufficient access controls]. Without timely remediation of the Critical and High findings, the likelihood of a successful breach is considered [HIGH / MEDIUM].",
  },
  {
    id: "attack_timeline", label: "Attack Timeline", icon: "⏱️", required: false,
    defaultFor: ["red_team","incident","breach","forensic"],
    reportTitle: "Attack Timeline",
    desc: "Chronological sequence of attack steps, from initial reconnaissance to final objective.",
    example: "The following timeline documents the key events observed during the engagement, from initial reconnaissance through to objective completion. All timestamps are in [UTC / CET].\n\nNote: Steps marked with [ASSUMED] represent inferred adversary actions based on artefacts collected during the investigation. Steps marked with [CONFIRMED] were directly observed or evidenced by logs.",
  },
  {
    id: "attack_narrative", label: "Attack Narrative", icon: "⚔️", required: false,
    defaultFor: ["red_team","pentest"],
    reportTitle: "Attack Narrative",
    desc: "Narrative walkthrough of the full kill chain: initial access → lateral movement → objective.",
    example: "This section provides a detailed narrative of the attack chain followed during the engagement, describing each phase in the context of the MITRE ATT&CK framework.\n\nInitial Access was achieved via [technique, e.g. spear-phishing / exposed RDP / public-facing vulnerability]. From the initial foothold on [hostname], the team performed [internal reconnaissance / credential harvesting / lateral movement] to reach [target system/data].\n\nThe complete attack chain demonstrates that a determined adversary with moderate resources could [describe business impact, e.g. exfiltrate customer data / disrupt critical services] without triggering existing detection controls.",
  },
  {
    id: "attack_paths", label: "Attack Paths", icon: "🔀", required: false,
    defaultFor: ["red_team","pentest"],
    reportTitle: "Attack Paths",
    desc: "Exploitation chains showing how vulnerabilities chain together to reach critical assets.",
    example: "The table below maps the observed and potential attack paths identified during the assessment, showing the progression from initial access to high-value targets.\n\nPath 1 — External to Domain Admin: [CVE-XXXX (RCE on web server)] → [Credential dump via LSASS] → [Pass-the-hash to DC] → [Domain compromise]\n\nEach path is rated by Complexity (Low/Medium/High) and Business Impact. Paths with Low complexity and High impact should be treated as critical remediation priorities.",
  },
  {
    id: "ioc", label: "Indicators of Compromise", icon: "🔍", required: false,
    defaultFor: ["incident","breach","forensic","malware","threat_intel"],
    reportTitle: "Indicators of Compromise",
    desc: "File hashes, IP addresses, domains, registry keys and other artefacts for threat hunting.",
    example: "The following indicators were identified during the assessment and should be immediately ingested into SIEM, EDR, and threat intelligence platforms for detection and hunting purposes.\n\nAll network-based IoCs should be blocked at the perimeter firewall and web proxy. Host-based IoCs should be added to endpoint detection signatures. Indicators marked [ACTIVE] were observed during the engagement period and may indicate ongoing attacker presence.",
  },
  {
    id: "vuln_details", label: "Vulnerability Details", icon: "🐛", required: false,
    defaultFor: ["pentest","va","red_team","web_app","mobile_app","cloud","network","retest","it_infra","code_review","patch_mgmt","compliance"],
    reportTitle: "Vulnerability Overview",
    desc: "Full findings list with severity, CVSS score, EPSS, affected host/port, description, evidence, and remediation guidance.",
    example: "The following section details all vulnerabilities identified during the assessment, ordered by severity. Each finding includes a risk rating, technical description, evidence of exploitability, and specific remediation guidance.\n\nSeverity ratings follow the CVSS v3.1 standard. EPSS scores represent the probability of exploitation within the next 30 days. Findings marked [CONFIRMED EXPLOITABLE] were demonstrated during the engagement.",
  },
  {
    id: "host_breakdown", label: "Host Breakdown", icon: "🖥️", required: false,
    defaultFor: ["pentest","va","network","cloud","it_infra"],
    reportTitle: "Host Breakdown",
    desc: "Findings grouped by host/IP to help system owners understand their specific exposure.",
    example: "This section groups all identified vulnerabilities by affected host to facilitate remediation ownership assignment. Each system owner should review the findings attributed to systems under their responsibility and agree remediation timelines accordingly.\n\nHosts are ordered by total number of Critical and High severity findings. Systems with no findings are not listed.",
  },
  {
    id: "remediation_plan", label: "Remediation Plan", icon: "🔧", required: false,
    defaultFor: ["pentest","va","remediation","retest","patch_mgmt","compliance"],
    reportTitle: "Remediation Plan",
    desc: "Prioritised action list with recommended owners, effort estimates, and suggested deadlines.",
    example: "The following remediation plan prioritises all identified findings by severity and business impact. Recommended timelines assume standard operational capacity; they should be adjusted based on the organisation's change management process.\n\nSuggested SLAs: Critical — remediate within 24–72 hours; High — within 2 weeks; Medium — within 30 days; Low / Informational — within 90 days or next scheduled maintenance window.\n\nAll remediations should be verified through retesting before the finding is marked as resolved.",
  },
  {
    id: "diff_retest", label: "Retest Comparison", icon: "🔄", required: false,
    defaultFor: ["retest"],
    reportTitle: "Retest Comparison",
    desc: "Side-by-side comparison of current findings against the previous assessment: new, fixed, and persistent issues.",
    example: "This section compares the current assessment results against the findings documented in the previous report ([Previous Report Date / Reference]). The comparison measures remediation effectiveness and identifies any regression or newly introduced vulnerabilities.\n\nOf the [N] findings from the previous assessment: [N] have been fully remediated, [N] are partially remediated, [N] remain open, and [N] new findings were identified in this round.",
  },
  {
    id: "risk_register", label: "Risk Register", icon: "📝", required: false,
    defaultFor: ["risk_register","compliance","it_audit"],
    reportTitle: "Risk Register",
    desc: "Formal risk catalog with risk owners, likelihood/impact ratings, and acceptance or mitigation decisions.",
    example: "The risk register below documents all identified risks, their current treatment status, and assigned ownership. Risks marked as 'Accepted' have been formally acknowledged by the Risk Owner and do not require immediate remediation within the scope of this assessment.\n\nRisks should be reviewed on a [quarterly / annual] basis or whenever a material change to the environment occurs.",
  },
  {
    id: "compliance_matrix", label: "Compliance Matrix", icon: "✅", required: false,
    defaultFor: ["compliance","it_audit"],
    reportTitle: "Compliance Matrix",
    desc: "Control-by-control compliance status mapped against the applicable framework (ISO 27001, NIS2, PCI-DSS, etc.).",
    example: "The following matrix maps the assessment findings against the controls of [Framework Name, e.g. ISO/IEC 27001:2022 / NIS2 / PCI-DSS v4.0]. Each control is rated as: Compliant, Partially Compliant, Non-Compliant, or Not Assessed.\n\nNon-Compliant controls are directly linked to one or more findings in the Vulnerability Details section. Remediation of the associated findings is expected to bring those controls to a Compliant state.",
  },
  {
    id: "osint_findings", label: "OSINT Findings", icon: "🌐", required: false,
    defaultFor: ["osint","breach"],
    reportTitle: "OSINT Findings",
    desc: "Public exposure analysis: leaked credentials, exposed infrastructure, data breach records, and brand mentions.",
    example: "Open-source intelligence (OSINT) gathering was conducted using passive techniques only, without directly interacting with the target systems. The following findings represent information that is publicly accessible and could be leveraged by a threat actor during pre-attack reconnaissance.\n\nAll data was collected from publicly available sources including breach databases, certificate transparency logs, Shodan, and social media platforms. No exploitation or active scanning was performed.",
  },
  {
    id: "digital_footprint", label: "Digital Footprint", icon: "🌍", required: false,
    defaultFor: ["osint"],
    reportTitle: "Digital Footprint",
    desc: "Map of externally visible assets: subdomains, exposed services, certificates, and public code repositories.",
    example: "Passive reconnaissance activities mapped the organisation's publicly exposed attack surface. The following findings represent assets that are directly reachable from the internet and may not be fully accounted for in the organisation's asset inventory.\n\nSubdomains, IP ranges, and cloud storage buckets discovered during this phase should be reviewed for necessity and properly hardened or decommissioned if no longer required.",
  },
  {
    id: "credential_exposure", label: "Credential Exposure", icon: "🔑", required: false,
    defaultFor: ["osint","breach"],
    reportTitle: "Credential Exposure",
    desc: "Leaked credentials identified in breach databases, paste sites, and dark web sources.",
    example: "The following credentials associated with the organisation's domains were identified through analysis of publicly known data breach repositories. These credentials may be used in credential stuffing, password spraying, or targeted phishing attacks.\n\nAll exposed accounts should have their passwords reset immediately. Enabling multi-factor authentication (MFA) for all listed accounts is strongly recommended as an additional control, regardless of whether the password has been changed.",
  },
  {
    id: "mitre_mapping", label: "MITRE ATT&CK Mapping", icon: "🗺️", required: false,
    defaultFor: ["red_team","pentest","incident","threat_intel","malware"],
    reportTitle: "MITRE ATT&CK Mapping",
    desc: "Findings and observed techniques mapped to MITRE ATT&CK tactics and techniques.",
    example: "The techniques observed during this engagement have been mapped to the MITRE ATT&CK Enterprise framework (v[version]) to support detection engineering, threat modelling, and security control gap analysis.\n\nOrganisations are encouraged to use this mapping as input to their threat detection roadmap. Tactics and techniques with low or no detection coverage represent the highest priority for SIEM rule development and EDR tuning.",
  },
  {
    id: "detection_gap", label: "Detection Gap Analysis", icon: "🔭", required: false,
    defaultFor: ["red_team","incident"],
    reportTitle: "Detection Gap Analysis",
    desc: "Assessment of which attack techniques were not detected by existing monitoring and SIEM/EDR tooling.",
    example: "This section identifies areas where the organisation's current detection and monitoring capabilities were insufficient to identify or alert on attacker activity during the engagement.\n\nFor each undetected technique, a recommended detection approach is provided. Detection rules and SIGMA signatures can be provided as a separate deliverable upon request. Gaps are rated by Detection Priority: Critical (should be addressed immediately), High (address within 30 days), and Medium (address within 90 days).",
  },
  {
    id: "owasp_coverage", label: "OWASP Coverage", icon: "🔒", required: false,
    defaultFor: ["web_app"],
    reportTitle: "OWASP Coverage",
    desc: "Findings mapped to the OWASP Top 10 risk categories for web applications.",
    example: "This section maps all identified vulnerabilities to the OWASP Top 10 (current edition) to provide a standardised view of the application's security posture against well-known web application risk categories.\n\nCategories with multiple findings indicate systemic weaknesses in the application's design or implementation. These should be addressed through targeted secure development training and framework-level controls rather than individual bug fixes.",
  },
  {
    id: "masvs_coverage", label: "MASVS Coverage", icon: "📱", required: false,
    defaultFor: ["mobile_app"],
    reportTitle: "MASVS Coverage",
    desc: "Findings mapped to OWASP MASVS controls for iOS/Android mobile applications.",
    example: "Findings are mapped to the OWASP Mobile Application Security Verification Standard (MASVS v[version]) to assess coverage across the security domains: Architecture, Data Storage, Cryptography, Authentication, Network Communication, Platform Interaction, and Code Quality.\n\nThe target verification level for this assessment was [MASVS-L1 / MASVS-L2]. Controls marked as Fail represent direct findings. Controls marked as Partial require additional hardening to meet the full standard.",
  },
  {
    id: "network_overview", label: "Network Overview", icon: "🌐", required: false,
    defaultFor: ["network","it_infra"],
    reportTitle: "Network Overview",
    desc: "Discovered hosts, open services, network topology, and exposure summary.",
    example: "Network discovery identified [N] live hosts across the assessed IP ranges. The following section summarises the network topology, exposed services, and key observations relevant to the overall security posture.\n\nServices exposed to [external / internal] networks that were not expected in the scope documentation have been flagged for review. All management interfaces (SSH, RDP, SNMP, web admin panels) accessible from untrusted network segments are highlighted as priority findings.",
  },
  {
    id: "cloud_posture_overview", label: "Cloud Posture Overview", icon: "☁️", required: false,
    defaultFor: ["cloud"],
    reportTitle: "Cloud Posture Overview",
    desc: "Security posture score across cloud domains: IAM, Storage, Network, Compute, Logging, and Encryption.",
    example: "This section provides a high-level assessment of the cloud environment's security posture across the key security domains. Findings are aggregated by domain to highlight areas of concentration risk.\n\nThe assessment covered resources in [AWS / Azure / GCP] within the following accounts/subscriptions: [list]. Resources tagged as out-of-scope in the Statement of Work were not assessed. Cloud-native security benchmarks (CIS [Provider] Foundations Benchmark v[version]) were used as the primary reference.",
  },
  {
    id: "recommendations", label: "Recommendations", icon: "💡", required: false,
    defaultFor: ["executive","red_team","social_eng","incident","threat_intel","arch_review","dr","lessons_learned"],
    reportTitle: "Recommendations",
    desc: "Strategic security recommendations to address root causes and improve long-term security posture.",
    example: "Based on the findings of this assessment, the following strategic recommendations are provided to address the identified root causes and improve the organisation's overall security posture. These recommendations complement the technical remediations detailed in the Remediation Plan.\n\nRecommendations are categorised as: Quick Win (implementable within 2 weeks with minimal resource), Short-Term (1–3 months), and Strategic (3–12 months, may require budget or programme investment).",
  },
  {
    id: "appendix", label: "Appendix", icon: "📎", required: false,
    defaultFor: ["pentest","va","red_team","web_app","forensic","malware","code_review"],
    reportTitle: "Appendices",
    desc: "Supplementary materials: raw tool output, glossary, methodology references, and supporting evidence.",
    example: "This appendix contains supplementary materials referenced throughout the report. Raw tool outputs and additional evidence are available upon request and can be provided in a separate secure file transfer.\n\nGlossary of key terms, acronyms, and severity rating definitions used in this report are included below for reference.",
  },
  {
    id: "last_page", label: "Last Page / Disclaimer", icon: "📌", required: true, defaultFor: "all",
    reportTitle: "Last Page",
    desc: "Legal disclaimer, confidentiality notice, and document closure — auto-generated from organisation profile.",
    example: "",
  },
];

export function getDefaultSections(reportTypeId: ReportTypeId): string[] {
  return REPORT_SECTIONS
    .filter((s) => s.required || s.defaultFor === "all" || (s.defaultFor as ReportTypeId[]).includes(reportTypeId))
    .map((s) => s.id);
}

// ─── Chart Definitions ────────────────────────────────────────────────────────

export interface ChartDef {
  id: string;
  label: string;
  icon: string;
  desc: string;
  section: string;
  variants: string[];
  defaultVariant: string;
  recommendedFor: ReportTypeId[];
}

export const CHARTS: ChartDef[] = [
  { id: "severity_donut",    label: "Severity Distribution",  icon: "🍩", desc: "Donut/pie of vuln counts by severity",       section: "Executive",  variants: ["Donut","Pie"],          defaultVariant: "Donut",           recommendedFor: ["pentest","va","red_team","web_app","cloud","network","executive","retest"] },
  { id: "risk_gauge",        label: "Risk Gauge",             icon: "🎯", desc: "Overall risk score (0–100)",                 section: "Executive",  variants: ["Gauge","Semaphore"],    defaultVariant: "Gauge",           recommendedFor: ["pentest","va","executive","compliance","retest"] },
  { id: "trend_line",        label: "Historical Trend",       icon: "📈", desc: "Vuln count over time across sub-projects",   section: "Executive",  variants: ["Line","Area"],          defaultVariant: "Line",            recommendedFor: ["pentest","va","retest","risk_register"] },
  { id: "top_hosts_bar",     label: "Top 5 Exposed Hosts",    icon: "🖥️", desc: "Hosts with most critical vulnerabilities",   section: "Executive",  variants: ["Horizontal Bar"],      defaultVariant: "Horizontal Bar",  recommendedFor: ["pentest","va","network","cloud","executive"] },
  { id: "risk_matrix",       label: "Risk Matrix",            icon: "🗓️", desc: "Likelihood × Impact heatmap",                section: "Results",    variants: ["Heatmap","Bubble"],    defaultVariant: "Heatmap",         recommendedFor: ["pentest","va","red_team","compliance","risk_register"] },
  { id: "vuln_by_category",  label: "Vulns by Category",      icon: "📊", desc: "Findings grouped by type (OWASP, etc.)",    section: "Results",    variants: ["Bar","Grouped Bar"],   defaultVariant: "Bar",             recommendedFor: ["web_app","mobile_app","pentest","va","compliance"] },
  { id: "remediation_effort",label: "Remediation Effort",     icon: "🔧", desc: "Estimated effort by severity band",          section: "Results",    variants: ["Stacked Bar"],         defaultVariant: "Stacked Bar",     recommendedFor: ["remediation","pentest","va","retest"] },
  { id: "fixed_vs_open",     label: "Fixed vs Open",          icon: "✅", desc: "Remediation progress",                       section: "Results",    variants: ["Donut","Progress Bar"],defaultVariant: "Donut",           recommendedFor: ["retest","remediation","patch_mgmt"] },
  { id: "cvss_radar",        label: "CVSS Breakdown",         icon: "🕸️", desc: "CVSS vector components (AV/AC/PR/UI/…)",    section: "Technical",  variants: ["Radar"],               defaultVariant: "Radar",           recommendedFor: ["pentest","va","web_app","cloud","network"] },
  { id: "epss_distribution", label: "EPSS Distribution",      icon: "🎲", desc: "Exploit probability distribution",           section: "Technical",  variants: ["Histogram","Bar"],     defaultVariant: "Histogram",       recommendedFor: ["pentest","va","threat_intel","patch_mgmt"] },
  { id: "vuln_by_host",      label: "Vulns per Host",         icon: "🔢", desc: "Breakdown of findings per IP/hostname",      section: "Technical",  variants: ["Bar","Treemap"],       defaultVariant: "Bar",             recommendedFor: ["pentest","va","network","cloud","it_infra"] },
];

// ─── Audience-aware chart config ──────────────────────────────────────────────

export type AudienceLevel = "executive" | "management" | "technical";

export interface ChartForType {
  /** Audience levels for which this chart is auto-enabled */
  enabledFor: AudienceLevel[];
  /**
   * Chart is structurally inapplicable for this report type.
   * Shown greyed-out in UI, cannot be toggled on.
   */
  notApplicable?: boolean;
}

/**
 * Per ogni report type: per ogni chart_id, quali audience lo mostrano di default
 * e se il grafico è N/A strutturalmente per quel tipo.
 *
 * Chart IDs corrispondono a quelli in CHARTS sopra.
 * Trascrizione diretta da REPORT_CHARTS_SPEC.md (sezione 3).
 *
 * Chart non listati per un report type = off by default ma attivabili manualmente.
 * Chart con notApplicable: true = greyed-out, sempre disabilitati.
 */
export const REPORT_TYPE_CHARTS: Partial<Record<ReportTypeId, Record<string, ChartForType>>> = {

  // ── 1. Vulnerability Assessment ──────────────────────────────────────────
  va: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: ["executive","management","technical"] },
    top_hosts_bar:      { enabledFor: ["management","technical"] },
    risk_matrix:        { enabledFor: ["executive","management","technical"] },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },
    cvss_radar:         { enabledFor: ["technical"] },
    epss_distribution:  { enabledFor: ["management","technical"] },
    vuln_by_host:       { enabledFor: ["management","technical"] },
  },

  // ── 2. Penetration Test ───────────────────────────────────────────────────
  pentest: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: ["management","technical"] },
    top_hosts_bar:      { enabledFor: ["management","technical"] },
    risk_matrix:        { enabledFor: ["executive","management","technical"] },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },
    cvss_radar:         { enabledFor: ["technical"] },
    epss_distribution:  { enabledFor: ["management","technical"] },
    vuln_by_host:       { enabledFor: ["technical"] },
  },

  // ── 3. Web Application Security ──────────────────────────────────────────
  web_app: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: [] },                                      // off by default — no history in typical webapp tests
    top_hosts_bar:      { enabledFor: ["management","technical"] },              // recontextualised as "top vulnerable endpoints"
    risk_matrix:        { enabledFor: ["management","technical"] },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // OWASP Top 10 dominant
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },
    cvss_radar:         { enabledFor: ["technical"] },
    epss_distribution:  { enabledFor: ["management","technical"] },
    vuln_by_host:       { enabledFor: [] },                                      // URL-oriented, not host-oriented
  },

  // ── 4. Network Security Assessment ───────────────────────────────────────
  network: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: [] },
    top_hosts_bar:      { enabledFor: ["management","technical"] },
    risk_matrix:        { enabledFor: ["executive","management","technical"] },
    vuln_by_category:   { enabledFor: ["management","technical"] },              // network-specific: SSL/TLS, SMB, RDP…
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },
    cvss_radar:         { enabledFor: ["technical"] },
    epss_distribution:  { enabledFor: ["technical"] },
    vuln_by_host:       { enabledFor: ["management","technical"] },              // dominant chart for network reports
  },

  // ── 5. Cloud Security Assessment ─────────────────────────────────────────
  cloud: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: [] },
    top_hosts_bar:      { enabledFor: ["management","technical"] },              // recontextualised as "top exposed resources"
    risk_matrix:        { enabledFor: ["management","technical"] },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // IAM, Storage, Network, Logging…
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },
    cvss_radar:         { enabledFor: ["technical"] },
    epss_distribution:  { enabledFor: ["management","technical"] },
    vuln_by_host:       { enabledFor: [] },                                      // cloud uses resource types, not traditional hosts
  },

  // ── 6. Mobile Application Security ───────────────────────────────────────
  mobile_app: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: [] },
    top_hosts_bar:      { enabledFor: [], notApplicable: true },                 // no hosts in mobile apps
    risk_matrix:        { enabledFor: ["management","technical"] },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // MASVS categories dominant
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: [] },
    cvss_radar:         { enabledFor: ["technical"] },
    epss_distribution:  { enabledFor: ["technical"] },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },

  // ── 7. Red Team ───────────────────────────────────────────────────────────
  red_team: {
    severity_donut:     { enabledFor: ["management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },              // score = % objectives reached × avg severity
    trend_line:         { enabledFor: ["management","technical"] },
    top_hosts_bar:      { enabledFor: ["management","technical"] },              // "top 5 compromised hosts"
    risk_matrix:        { enabledFor: [] },
    vuln_by_category:   { enabledFor: ["management","technical"] },              // MITRE ATT&CK tactics
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },
    cvss_radar:         { enabledFor: ["technical"] },
    epss_distribution:  { enabledFor: ["technical"] },
    vuln_by_host:       { enabledFor: ["technical"] },
  },

  // ── 8. OSINT ──────────────────────────────────────────────────────────────
  osint: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: [] },
    top_hosts_bar:      { enabledFor: ["management","technical"] },              // "top 5 most exposed assets"
    risk_matrix:        { enabledFor: [], notApplicable: true },                 // no CVSS/host structure in OSINT findings
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // CREDENTIAL_LEAK, EXPOSED_ASSET…
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: [], notApplicable: true },
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: [], notApplicable: true },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },

  // ── 9. Threat Intelligence ────────────────────────────────────────────────
  threat_intel: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: ["management","technical"] },
    top_hosts_bar:      { enabledFor: [], notApplicable: true },
    risk_matrix:        { enabledFor: [], notApplicable: true },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // APT, RANSOMWARE, PHISHING…
    remediation_effort: { enabledFor: [], notApplicable: true },
    fixed_vs_open:      { enabledFor: [], notApplicable: true },
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: ["management","technical"] },              // CVEs cited with EPSS score
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },

  // ── 10. Social Engineering / Phishing ────────────────────────────────────
  social_eng: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },              // click rate normalised 0-100
    trend_line:         { enabledFor: ["management","technical"] },
    top_hosts_bar:      { enabledFor: [], notApplicable: true },
    risk_matrix:        { enabledFor: [], notApplicable: true },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // by department or behaviour type
    remediation_effort: { enabledFor: ["management"] },                          // training effort by department
    fixed_vs_open:      { enabledFor: ["management","technical"] },              // here = "reported vs not reported"
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: [], notApplicable: true },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },

  // ── 11. Incident Response ─────────────────────────────────────────────────
  incident: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: ["management","technical"] },
    top_hosts_bar:      { enabledFor: ["management","technical"] },              // "top 5 most impacted systems"
    risk_matrix:        { enabledFor: [], notApplicable: true },
    vuln_by_category:   { enabledFor: ["management","technical"] },              // impact type: DATA, SERVICE…
    remediation_effort: { enabledFor: [], notApplicable: true },
    fixed_vs_open:      { enabledFor: [], notApplicable: true },
    cvss_radar:         { enabledFor: ["technical"] },                           // only if CVEs were exploited
    epss_distribution:  { enabledFor: ["technical"] },                           // only if CVEs identified
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },

  // ── 12. Forensic Investigation ────────────────────────────────────────────
  forensic: {
    severity_donut:     { enabledFor: ["management","technical"] },
    risk_gauge:         { enabledFor: [], notApplicable: true },
    trend_line:         { enabledFor: [], notApplicable: true },
    top_hosts_bar:      { enabledFor: [], notApplicable: true },
    risk_matrix:        { enabledFor: [], notApplicable: true },
    vuln_by_category:   { enabledFor: ["management","technical"] },              // FILE, LOG, REGISTRY, MEMORY, NETWORK
    remediation_effort: { enabledFor: [], notApplicable: true },
    fixed_vs_open:      { enabledFor: [], notApplicable: true },
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: [], notApplicable: true },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },

  // ── 13. Malware Analysis ──────────────────────────────────────────────────
  malware: {
    severity_donut:     { enabledFor: ["management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },              // estimated dangerousness
    trend_line:         { enabledFor: [], notApplicable: true },
    top_hosts_bar:      { enabledFor: [], notApplicable: true },
    risk_matrix:        { enabledFor: [], notApplicable: true },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // PERSISTENCE, EVASION, C2…
    remediation_effort: { enabledFor: [], notApplicable: true },
    fixed_vs_open:      { enabledFor: [], notApplicable: true },
    cvss_radar:         { enabledFor: ["technical"] },                           // only if sample contains CVEs
    epss_distribution:  { enabledFor: ["technical"] },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },

  // ── 14. Breach Notification ───────────────────────────────────────────────
  breach: {
    severity_donut:     { enabledFor: ["management","technical"] },
    risk_gauge:         { enabledFor: [], notApplicable: true },
    trend_line:         { enabledFor: [], notApplicable: true },
    top_hosts_bar:      { enabledFor: [], notApplicable: true },
    risk_matrix:        { enabledFor: [], notApplicable: true },
    vuln_by_category:   { enabledFor: ["management"] },                          // type of violation by data category
    remediation_effort: { enabledFor: [], notApplicable: true },
    fixed_vs_open:      { enabledFor: [], notApplicable: true },
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: [], notApplicable: true },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },

  // ── 15. Post-Incident Lessons Learned ────────────────────────────────────
  lessons_learned: {
    severity_donut:     { enabledFor: [], notApplicable: true },
    risk_gauge:         { enabledFor: [], notApplicable: true },
    trend_line:         { enabledFor: ["executive","management","technical"] },  // incident trend before/after
    top_hosts_bar:      { enabledFor: [], notApplicable: true },
    risk_matrix:        { enabledFor: [], notApplicable: true },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // PROCESS, TOOL, TRAINING, DETECTION
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },  // improvement actions: done vs open
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: [], notApplicable: true },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },

  // ── 16. Remediation Plan ──────────────────────────────────────────────────
  remediation: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: [], notApplicable: true },
    trend_line:         { enabledFor: ["management","technical"] },              // closure trend over time
    top_hosts_bar:      { enabledFor: [], notApplicable: true },
    risk_matrix:        { enabledFor: [], notApplicable: true },
    vuln_by_category:   { enabledFor: [] },
    remediation_effort: { enabledFor: ["management","technical"] },              // dominant chart
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },  // dominant chart
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: [], notApplicable: true },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },

  // ── 17. Retest / Verification ─────────────────────────────────────────────
  retest: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: [] },                                       // conditional: available but off
    trend_line:         { enabledFor: ["management","technical"] },              // compare previous vs current
    top_hosts_bar:      { enabledFor: [] },
    risk_matrix:        { enabledFor: [] },
    vuln_by_category:   { enabledFor: [] },
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },  // dominant chart
    cvss_radar:         { enabledFor: [] },
    epss_distribution:  { enabledFor: [] },
    vuln_by_host:       { enabledFor: [] },
  },

  // ── 18. Risk Register ─────────────────────────────────────────────────────
  risk_register: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },              // aggregated risk score
    trend_line:         { enabledFor: [] },
    top_hosts_bar:      { enabledFor: [], notApplicable: true },
    risk_matrix:        { enabledFor: ["executive","management","technical"] },  // dominant — inherent + residual
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // TECHNICAL, OPERATIONAL, COMPLIANCE…
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },  // risks: treated vs open
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: [], notApplicable: true },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },

  // ── 19. Patch Management ──────────────────────────────────────────────────
  patch_mgmt: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },              // % patch non-compliance
    trend_line:         { enabledFor: ["management","technical"] },
    top_hosts_bar:      { enabledFor: ["management","technical"] },              // top 5 most non-compliant hosts
    risk_matrix:        { enabledFor: [], notApplicable: true },
    vuln_by_category:   { enabledFor: ["management","technical"] },              // by OS / product / severity
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },
    cvss_radar:         { enabledFor: ["technical"] },
    epss_distribution:  { enabledFor: ["management","technical"] },              // EPSS for CVEs in pending patches
    vuln_by_host:       { enabledFor: [], notApplicable: true },                 // top_hosts_bar covers this
  },

  // ── 20. Compliance Gap Assessment ────────────────────────────────────────
  compliance: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },              // % compliance overall
    trend_line:         { enabledFor: ["management","technical"] },
    top_hosts_bar:      { enabledFor: [] },
    risk_matrix:        { enabledFor: [] },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // gap by framework domain — dominant
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },
    cvss_radar:         { enabledFor: [] },
    epss_distribution:  { enabledFor: [] },
    vuln_by_host:       { enabledFor: [] },
  },

  // ── 21. IT Infrastructure Assessment ─────────────────────────────────────
  it_infra: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: [] },
    top_hosts_bar:      { enabledFor: ["management","technical"] },              // "top 5 most critical assets"
    risk_matrix:        { enabledFor: [] },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // CONFIGURATION, VERSIONING…
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },
    cvss_radar:         { enabledFor: [] },
    epss_distribution:  { enabledFor: [] },
    vuln_by_host:       { enabledFor: ["technical"] },
  },

  // ── 22. Code Review ───────────────────────────────────────────────────────
  code_review: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: [] },
    top_hosts_bar:      { enabledFor: ["management","technical"] },              // recontextualised as "top files/modules"
    risk_matrix:        { enabledFor: [] },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },  // INJECTION, AUTH, CRYPTO…
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: [] },
    cvss_radar:         { enabledFor: ["technical"] },                           // if CWE/CVSS available
    epss_distribution:  { enabledFor: ["management","technical"] },              // for vulnerable dependencies with CVEs
    vuln_by_host:       { enabledFor: [], notApplicable: true },                 // no hosts in code review
  },

  // ── Other types (no explicit spec — sensible defaults) ───────────────────
  executive: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: ["executive","management","technical"] },
    top_hosts_bar:      { enabledFor: ["management","technical"] },
    risk_matrix:        { enabledFor: [], notApplicable: true },
    vuln_by_category:   { enabledFor: ["management","technical"] },
    remediation_effort: { enabledFor: [] },
    fixed_vs_open:      { enabledFor: [] },
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: [], notApplicable: true },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },
  arch_review: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: [] },
    top_hosts_bar:      { enabledFor: [], notApplicable: true },
    risk_matrix:        { enabledFor: ["management","technical"] },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: [] },
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: [], notApplicable: true },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },
  dr: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: ["management","technical"] },
    top_hosts_bar:      { enabledFor: [] },
    risk_matrix:        { enabledFor: [] },
    vuln_by_category:   { enabledFor: ["management","technical"] },
    remediation_effort: { enabledFor: [] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: [], notApplicable: true },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },
  it_audit: {
    severity_donut:     { enabledFor: ["executive","management","technical"] },
    risk_gauge:         { enabledFor: ["executive","management"] },
    trend_line:         { enabledFor: [] },
    top_hosts_bar:      { enabledFor: [] },
    risk_matrix:        { enabledFor: ["management","technical"] },
    vuln_by_category:   { enabledFor: ["executive","management","technical"] },
    remediation_effort: { enabledFor: ["management","technical"] },
    fixed_vs_open:      { enabledFor: ["executive","management","technical"] },
    cvss_radar:         { enabledFor: [], notApplicable: true },
    epss_distribution:  { enabledFor: [], notApplicable: true },
    vuln_by_host:       { enabledFor: [], notApplicable: true },
  },
};

/**
 * Returns the default enabled/disabled state for all charts,
 * given a report type and the selected audience level.
 *
 * Rules:
 *  - notApplicable → always false (greyed-out)
 *  - enabledFor includes audience → true
 *  - not listed or enabledFor empty → false (available but off)
 *  - no config for this type → fallback to DEFAULT_CHARTS_ENABLED
 */
export function getDefaultChartsForAudience(
  reportTypeId: ReportTypeId | "",
  audience: AudienceLevel,
): Record<string, boolean> {
  if (!reportTypeId) return DEFAULT_CHARTS_ENABLED;
  const config = REPORT_TYPE_CHARTS[reportTypeId as ReportTypeId];
  if (!config) return DEFAULT_CHARTS_ENABLED;

  return Object.fromEntries(
    CHARTS.map((chart) => {
      const cfg = config[chart.id];
      if (!cfg || cfg.notApplicable) return [chart.id, false];
      return [chart.id, cfg.enabledFor.includes(audience)];
    }),
  );
}

// ─── Misc ─────────────────────────────────────────────────────────────────────

export const AUDIENCE_LABELS: Record<string, string> = {
  executive: "Executive / C-Level",
  management: "Management / CISO",
  technical: "Technical Lead / Engineer",
};

export const CLASSIFICATION_LEVELS = ["PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED","TOP SECRET"];
export const METHODOLOGIES = ["OWASP Testing Guide","PTES","OSSTMM","NIST SP 800-115","NIST CSF","ISO 27001","MITRE ATT&CK","TIBER-EU","DORA"];
export const FONTS = ["Inter","Roboto","Source Sans Pro","Open Sans","Montserrat","IBM Plex Sans","Ubuntu Mono"];

export const RISK_LEVELS: RiskLevel[] = ["critical", "high", "medium", "low", "info"];
export const VULN_STATUSES = ["open", "fixed", "accepted", "retest"] as const;
export type VulnStatusFilter = typeof VULN_STATUSES[number];

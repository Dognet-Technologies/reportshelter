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
  label: string;
  icon: string;
  desc: string;
  required: boolean;
  defaultFor: ReportTypeId[] | "all";
}

export const REPORT_SECTIONS: ReportSection[] = [
  { id: "cover",             label: "Cover Page",              icon: "📄", desc: "Title, client info, date, classification", required: true,  defaultFor: "all" },
  { id: "toc",               label: "Table of Contents",       icon: "📋", desc: "Auto-generated TOC",                        required: false, defaultFor: ["pentest","va","red_team","web_app","mobile_app","cloud","network","compliance","forensic","it_infra"] },
  { id: "executive_summary", label: "Executive Summary",       icon: "📊", desc: "KPIs, overall risk, key findings at a glance", required: false, defaultFor: ["pentest","va","red_team","web_app","cloud","network","executive","retest","compliance","it_infra"] },
  { id: "scope",             label: "Scope & Methodology",     icon: "🎯", desc: "Testing scope, assets, methodology used",   required: false, defaultFor: ["pentest","va","red_team","web_app","mobile_app","cloud","network","it_infra","code_review"] },
  { id: "risk_summary",      label: "Risk Summary",            icon: "⚠️", desc: "Severity distribution charts, risk gauge",  required: false, defaultFor: ["pentest","va","red_team","web_app","cloud","network","executive","risk_register","compliance","retest"] },
  { id: "attack_timeline",   label: "Attack Timeline",         icon: "⏱️", desc: "Chronological narrative of attack steps",   required: false, defaultFor: ["red_team","incident","breach","forensic"] },
  { id: "ioc",               label: "Indicators of Compromise",icon: "🔍", desc: "IoCs, TTPs, threat indicators, hashes",     required: false, defaultFor: ["incident","breach","forensic","malware","threat_intel"] },
  { id: "vuln_details",      label: "Vulnerability Details",   icon: "🐛", desc: "Full findings with CVSS, EPSS, evidence",   required: false, defaultFor: ["pentest","va","red_team","web_app","mobile_app","cloud","network","retest","it_infra","code_review","patch_mgmt","compliance"] },
  { id: "host_breakdown",        label: "Host Breakdown",           icon: "🖥️", desc: "Findings grouped by host / IP",                      required: false, defaultFor: ["pentest","va","network","cloud","it_infra"] },
  { id: "remediation_plan",      label: "Remediation Plan",         icon: "🔧", desc: "Prioritized fixes with owners and deadlines",         required: false, defaultFor: ["pentest","va","remediation","retest","patch_mgmt","compliance"] },
  { id: "diff_retest",           label: "Retest Comparison",        icon: "🔄", desc: "New / Fixed / Persistent comparison",                required: false, defaultFor: ["retest"] },
  { id: "risk_register",         label: "Risk Register",            icon: "📝", desc: "Risk catalog with acceptance decisions",             required: false, defaultFor: ["risk_register","compliance","it_audit"] },
  { id: "compliance_matrix",     label: "Compliance Matrix",        icon: "✅", desc: "Control-by-control compliance status",               required: false, defaultFor: ["compliance","it_audit"] },
  { id: "osint_findings",        label: "OSINT Findings",           icon: "🌐", desc: "Public exposure, leaked data, footprint",            required: false, defaultFor: ["osint","breach"] },
  { id: "recommendations",       label: "Recommendations",          icon: "💡", desc: "Strategic security recommendations",                 required: false, defaultFor: ["executive","red_team","social_eng","incident","threat_intel","arch_review","dr","lessons_learned"] },
  { id: "appendix",              label: "Appendix",                 icon: "📎", desc: "Raw tool outputs, references, glossary",             required: false, defaultFor: ["pentest","va","red_team","web_app","forensic","malware","code_review"] },
  // Sections added from REPORT_TEMPLATES_SPEC / REPORT_CHARTS_SPEC
  { id: "doc_control",           label: "Document Control",         icon: "📋", desc: "Version, classification, authors table",             required: false, defaultFor: ["pentest","va","red_team","web_app","mobile_app","cloud","network","compliance","it_infra","code_review","arch_review","osint","incident","forensic","malware","breach","lessons_learned"] },
  { id: "findings_summary",      label: "Findings Summary",         icon: "📊", desc: "Distribution charts + summary table",                required: false, defaultFor: ["va","pentest","red_team","web_app","mobile_app","cloud","network","compliance","it_infra","code_review","risk_register","it_audit","dr"] },
  { id: "engagement_overview",   label: "Engagement Overview",      icon: "🗂️", desc: "Objectives, RoE, team, timeline",                    required: false, defaultFor: ["red_team"] },
  { id: "attack_narrative",      label: "Attack Narrative",         icon: "⚔️", desc: "Chronological narrative of attack phases",           required: false, defaultFor: ["red_team","pentest"] },
  { id: "attack_paths",          label: "Attack Paths",             icon: "🔀", desc: "Attack chain diagrams, exploit chains, Crown Jewels",required: false, defaultFor: ["red_team","pentest"] },
  { id: "mitre_mapping",         label: "MITRE ATT&CK Mapping",     icon: "🗺️", desc: "Techniques mapped to MITRE ATT&CK framework",       required: false, defaultFor: ["red_team","pentest","incident","threat_intel","malware"] },
  { id: "detection_gap",         label: "Detection Gap Analysis",   icon: "🔭", desc: "Coverage gaps in detection and monitoring",          required: false, defaultFor: ["red_team","incident"] },
  { id: "digital_footprint",     label: "Digital Footprint",        icon: "🌍", desc: "Public asset exposure, subdomains, leaked data",     required: false, defaultFor: ["osint"] },
  { id: "credential_exposure",   label: "Credential Exposure",      icon: "🔑", desc: "Leaked credentials and breach data",                 required: false, defaultFor: ["osint","breach"] },
  { id: "owasp_coverage",        label: "OWASP Coverage",           icon: "🔒", desc: "OWASP Top 10 category mapping",                     required: false, defaultFor: ["web_app"] },
  { id: "masvs_coverage",        label: "MASVS Coverage",           icon: "📱", desc: "OWASP MASVS control coverage",                      required: false, defaultFor: ["mobile_app"] },
  { id: "network_overview",      label: "Network Overview",         icon: "🌐", desc: "Discovered hosts, services, topology",              required: false, defaultFor: ["network","it_infra"] },
  { id: "cloud_posture_overview",label: "Cloud Posture Overview",    icon: "☁️", desc: "Score per cloud area (IAM, Storage, Network…)",    required: false, defaultFor: ["cloud"] },
  { id: "last_page",             label: "Last Page / Disclaimer",   icon: "📌", desc: "Legal disclaimer and document closure",             required: true,  defaultFor: "all" },
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

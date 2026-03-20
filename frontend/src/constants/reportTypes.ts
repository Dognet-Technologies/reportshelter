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
  { id: "host_breakdown",    label: "Host Breakdown",          icon: "🖥️", desc: "Findings grouped by host / IP",             required: false, defaultFor: ["pentest","va","network","cloud","it_infra"] },
  { id: "remediation_plan",  label: "Remediation Plan",        icon: "🔧", desc: "Prioritized fixes with owners and deadlines",required: false, defaultFor: ["pentest","va","remediation","retest","patch_mgmt","compliance"] },
  { id: "diff_retest",       label: "Retest Comparison",       icon: "🔄", desc: "New / Fixed / Persistent comparison",       required: false, defaultFor: ["retest"] },
  { id: "risk_register",     label: "Risk Register",           icon: "📝", desc: "Risk catalog with acceptance decisions",    required: false, defaultFor: ["risk_register","compliance","it_audit"] },
  { id: "compliance_matrix", label: "Compliance Matrix",       icon: "✅", desc: "Control-by-control compliance status",      required: false, defaultFor: ["compliance","it_audit"] },
  { id: "osint_findings",    label: "OSINT Findings",          icon: "🌐", desc: "Public exposure, leaked data, footprint",   required: false, defaultFor: ["osint","breach"] },
  { id: "recommendations",   label: "Recommendations",         icon: "💡", desc: "Strategic security recommendations",        required: false, defaultFor: ["executive","red_team","social_eng","incident","threat_intel","arch_review","dr","lessons_learned"] },
  { id: "appendix",          label: "Appendix",                icon: "📎", desc: "Raw tool outputs, references, glossary",    required: false, defaultFor: ["pentest","va","red_team","web_app","forensic","malware","code_review"] },
  { id: "last_page",         label: "Last Page / Disclaimer",  icon: "📌", desc: "Legal disclaimer and document closure",     required: true,  defaultFor: "all" },
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

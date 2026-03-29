/**
 * Sub-project detail page.
 *
 * Layout:
 *   1. Breadcrumb + header
 *   2. Stats row (severity counts)
 *   3. 5-button Report Config toolbar (Report Type / Charts / Style / Extra / Scans)
 *   4. Active config panel (full-width, collapsible)
 *   5. Main grid: vulnerability table (left) + exports + screenshots (right)
 */
import { useState, useCallback, useEffect, useRef } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useDropzone } from "react-dropzone";
import {
  Upload, Loader2, FileText, Download, Image, AlertCircle, CheckCircle2,
  Clock, RefreshCw, Plus, ChevronRight, ChevronLeft, Palette, Info,
  Database, ChevronDown, ChevronUp, X, ExternalLink,
} from "lucide-react";
import { format } from "date-fns";
import toast from "react-hot-toast";
import {
  useSubProject, useVulnerabilities, useUploadScan, useScanImports,
  useReportExports, useScreenshots, useUploadScreenshot, useLicenseStatus,
  useRetryScanImport, useCancelScanImport,
} from "@/api/hooks";
import { downloadReport } from "@/api/download";
import { useQueryClient } from "@tanstack/react-query";
import { Layout } from "@/components/Layout";
import { VulnerabilityTable } from "@/components/VulnerabilityTable";
import type { RiskLevel, VulnStatus, ScanImport } from "@/api/types";

// ─── Report Config Data ───────────────────────────────────────────────────────

type ReportTypeId =
  | "pentest" | "va" | "red_team" | "web_app" | "mobile_app"
  | "cloud" | "network" | "social_eng" | "incident" | "threat_intel"
  | "compliance" | "osint" | "executive"
  | "it_infra" | "code_review" | "arch_review" | "dr" | "it_audit"
  | "remediation" | "retest" | "risk_register" | "patch_mgmt"
  | "breach" | "forensic" | "malware" | "lessons_learned";

interface ReportTypeInfo {
  id: ReportTypeId;
  label: string;
  desc: string;
  audience: string[];
  category: string;
}

const REPORT_TYPES: ReportTypeInfo[] = [
  // Cybersecurity
  { id: "pentest",     label: "Penetration Test Report",        desc: "Black/grey/white box pentest results",           audience: ["executive","management","technical"], category: "Cybersecurity" },
  { id: "va",          label: "Vulnerability Assessment",        desc: "Systematic scan without exploitation",           audience: ["management","technical"],             category: "Cybersecurity" },
  { id: "red_team",    label: "Red Team Report",                 desc: "APT simulation with attack narrative",           audience: ["executive","management","technical"], category: "Cybersecurity" },
  { id: "web_app",     label: "Web Application Security",        desc: "OWASP Top 10, DAST/SAST findings",              audience: ["technical","management"],             category: "Cybersecurity" },
  { id: "mobile_app",  label: "Mobile Application Security",     desc: "iOS/Android, OWASP MASVS",                      audience: ["technical","management"],             category: "Cybersecurity" },
  { id: "cloud",       label: "Cloud Security Assessment",       desc: "AWS/Azure/GCP misconfig, IAM, exposure",         audience: ["technical","management"],             category: "Cybersecurity" },
  { id: "network",     label: "Network Security Assessment",     desc: "Segmentation, firewall rules, exposure",         audience: ["technical","management"],             category: "Cybersecurity" },
  { id: "social_eng",  label: "Social Engineering Report",       desc: "Phishing/vishing campaigns, results",           audience: ["executive","management"],             category: "Cybersecurity" },
  { id: "incident",    label: "Incident Response Report",        desc: "Post-incident: timeline, IoC, containment",     audience: ["executive","management","technical"], category: "Cybersecurity" },
  { id: "threat_intel",label: "Threat Intelligence Report",      desc: "TTPs, threat actors, emerging vulns",           audience: ["management","technical"],             category: "Cybersecurity" },
  { id: "compliance",  label: "Compliance Gap Assessment",       desc: "ISO 27001, NIS2, GDPR, PCI-DSS, DORA",         audience: ["executive","management"],             category: "Cybersecurity" },
  { id: "osint",       label: "OSINT Report",                    desc: "Public exposure, digital footprint",            audience: ["management","technical"],             category: "Cybersecurity" },
  { id: "executive",   label: "Executive Summary",               desc: "Non-technical synthesis for board/management",  audience: ["executive"],                          category: "Cybersecurity" },
  // IT General
  { id: "it_infra",    label: "IT Infrastructure Assessment",    desc: "General infrastructure status",                 audience: ["management","technical"],             category: "IT General" },
  { id: "code_review", label: "Code Review Report",              desc: "Static code analysis findings",                 audience: ["technical"],                          category: "IT General" },
  { id: "arch_review", label: "Architecture Review",             desc: "Architectural evaluation",                      audience: ["technical","management"],             category: "IT General" },
  { id: "dr",          label: "Disaster Recovery Assessment",    desc: "RTO/RPO, backup, continuity",                  audience: ["management","technical"],             category: "IT General" },
  { id: "it_audit",    label: "IT Audit",                        desc: "Compliance with procedures, asset inventory",   audience: ["management"],                         category: "IT General" },
  // Remediation
  { id: "remediation", label: "Remediation Plan",                desc: "Prioritized remediation plan with owners",      audience: ["management","technical"],             category: "Remediation" },
  { id: "retest",      label: "Retest / Verification Report",    desc: "Verify fixes from previous assessment",         audience: ["management","technical"],             category: "Remediation" },
  { id: "risk_register",label:"Risk Register",                   desc: "Risk catalog with risk acceptance",             audience: ["executive","management"],             category: "Remediation" },
  { id: "patch_mgmt",  label: "Patch Management Report",         desc: "Update status, pending CVEs",                   audience: ["management","technical"],             category: "Remediation" },
  // Breach & Incident
  { id: "breach",      label: "Breach Notification Report",      desc: "For authorities (GDPR Art. 33/34), clients",   audience: ["executive","management"],             category: "Breach & Incident" },
  { id: "forensic",    label: "Forensic Investigation Report",   desc: "Forensic analysis, chain of custody",           audience: ["technical","management"],             category: "Breach & Incident" },
  { id: "malware",     label: "Malware Analysis Report",         desc: "Sample analysis, IOC, behavior",                audience: ["technical"],                          category: "Breach & Incident" },
  { id: "lessons_learned",label:"Post-Incident Lessons Learned", desc: "RCA, process improvements",                    audience: ["executive","management"],             category: "Breach & Incident" },
];


const FONTS = ["Inter","Roboto","Source Sans Pro","Open Sans","Montserrat","IBM Plex Sans","Ubuntu Mono"];
const AUDIENCE_LABELS: Record<string, string> = {
  executive: "Executive / C-Level",
  management: "Management / CISO",
  technical: "Technical Lead / Engineer",
};
const CLASSIFICATION_LEVELS = ["PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED","TOP SECRET"];
const METHODOLOGIES = ["OWASP Testing Guide","PTES","OSSTMM","NIST SP 800-115","NIST CSF","ISO 27001","MITRE ATT&CK","TIBER-EU","DORA"];
const SCANNER_OPTIONS = [
  { value: "nmap",     label: "Nmap (XML)" },
  { value: "nikto",    label: "Nikto (XML)" },
  { value: "burp",     label: "Burp Suite (XML)" },
  { value: "zap",      label: "OWASP ZAP (XML/JSON)" },
  { value: "metasploit",label:"Metasploit (XML)" },
  { value: "openvas",  label: "OpenVAS / Greenbone (XML or CSV)" },
  { value: "nessus",   label: "Nessus (CSV)" },
  { value: "csv",      label: "Generic CSV" },
];

// ─── Config State Defaults ────────────────────────────────────────────────────

interface StyleConfig { font: string; primaryColor: string; secondaryColor: string; borderRadius: string; titleSize: string; evidenceStyle: string; watermark: string; }
interface ExtraConfig { classification: string; version: string; scope: string; engagement_type: string; methodologies: string[]; authors: string; references: string; }

const DEFAULT_STYLE: StyleConfig = { font: "Inter", primaryColor: "#3b82f6", secondaryColor: "#64748b", borderRadius: "md", titleSize: "md", evidenceStyle: "box", watermark: "" };
const DEFAULT_EXTRA: ExtraConfig  = { classification: "CONFIDENTIAL", version: "1.0", scope: "", engagement_type: "grey_box", methodologies: [], authors: "", references: "" };

// ─── Panel Type ───────────────────────────────────────────────────────────────

type PanelId = "report_type" | "style" | "extra" | "scans";

// ─── Sub-components ───────────────────────────────────────────────────────────

function ImportStatusBadge({ status }: { status: ScanImport["status"] }) {
  const config = {
    pending:    { icon: <Clock className="h-3 w-3" />,                    text: "Pending",    cls: "text-amber-400" },
    processing: { icon: <RefreshCw className="h-3 w-3 animate-spin" />,   text: "Processing", cls: "text-blue-400"  },
    done:       { icon: <CheckCircle2 className="h-3 w-3" />,             text: "Done",       cls: "text-green-400" },
    failed:     { icon: <AlertCircle className="h-3 w-3" />,              text: "Failed",     cls: "text-red-400"   },
  };
  const c = config[status];
  return <span className={`inline-flex items-center gap-1 text-xs ${c.cls}`}>{c.icon}{c.text}</span>;
}

// ─── Panel 1: Report Type ─────────────────────────────────────────────────────

interface ReportTypePanelProps {
  selectedType: ReportTypeId | "";
  audience: string[];
  onTypeChange: (t: ReportTypeId) => void;
  onAudienceChange: (a: string[]) => void;
}

function ReportTypePanel({ selectedType, audience, onTypeChange, onAudienceChange }: ReportTypePanelProps) {
  const categories = Array.from(new Set(REPORT_TYPES.map((r) => r.category)));
  const selectedInfo = REPORT_TYPES.find((r) => r.id === selectedType);

  function toggleAudience(key: string) {
    onAudienceChange(audience.includes(key) ? audience.filter((a) => a !== key) : [...audience, key]);
  }

  return (
    <div className="space-y-5">
      {categories.map((cat) => (
        <div key={cat}>
          <p className="text-xs text-slate-500 uppercase tracking-wider font-medium mb-2">{cat}</p>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
            {REPORT_TYPES.filter((r) => r.category === cat).map((rt) => (
              <button
                key={rt.id}
                onClick={() => { onTypeChange(rt.id); onAudienceChange(rt.audience); }}
                className={`text-left rounded-lg border px-3 py-2.5 text-xs transition-colors ${
                  selectedType === rt.id
                    ? "border-blue-500 bg-blue-950/60 text-blue-200"
                    : "border-slate-700 hover:border-slate-500 text-slate-300"
                }`}
              >
                <p className="font-medium leading-tight">{rt.label}</p>
                <p className="text-slate-500 mt-0.5 leading-tight">{rt.desc}</p>
              </button>
            ))}
          </div>
        </div>
      ))}

      {selectedInfo && (
        <div className="pt-3 border-t border-slate-800">
          <p className="text-xs text-slate-500 uppercase tracking-wider font-medium mb-2">Audience</p>
          <div className="flex gap-3 flex-wrap">
            {Object.entries(AUDIENCE_LABELS).map(([key, label]) => (
              <label key={key} className="flex items-center gap-2 cursor-pointer text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={audience.includes(key)}
                  onChange={() => toggleAudience(key)}
                  className="rounded border-slate-600 bg-slate-800 text-blue-500"
                />
                {label}
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Panel 2: Style ───────────────────────────────────────────────────────────

function StylePanel({ style, onChange }: { style: StyleConfig; onChange: (s: StyleConfig) => void }) {
  const set = (k: keyof StyleConfig, v: string) => onChange({ ...style, [k]: v });
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
      {/* Font */}
      <div>
        <label className="label">Font Family</label>
        <select value={style.font} onChange={(e) => set("font", e.target.value)} className="input w-full">
          {FONTS.map((f) => <option key={f} value={f} style={{ fontFamily: f }}>{f}</option>)}
        </select>
      </div>
      {/* Title size */}
      <div>
        <label className="label">Title Size</label>
        <select value={style.titleSize} onChange={(e) => set("titleSize", e.target.value)} className="input w-full">
          <option value="sm">Small</option>
          <option value="md">Medium</option>
          <option value="lg">Large</option>
          <option value="xl">Extra Large</option>
        </select>
      </div>
      {/* Border radius */}
      <div>
        <label className="label">Border Radius</label>
        <div className="flex gap-2 mt-1">
          {[["none","Sharp"],["sm","Soft"],["md","Rounded"],["lg","Pill"]].map(([v, l]) => (
            <button key={v} onClick={() => set("borderRadius", v)}
              className={`px-3 py-1 text-xs rounded border transition-colors ${style.borderRadius === v ? "border-blue-500 bg-blue-950/50 text-blue-200" : "border-slate-700 text-slate-400"}`}
            >{l}</button>
          ))}
        </div>
      </div>
      {/* Primary color */}
      <div>
        <label className="label">Primary Color</label>
        <div className="flex items-center gap-2 mt-1">
          <input type="color" value={style.primaryColor} onChange={(e) => set("primaryColor", e.target.value)}
            className="h-8 w-14 rounded cursor-pointer bg-slate-800 border border-slate-700 p-0.5" />
          <span className="text-xs text-slate-400 font-mono">{style.primaryColor}</span>
        </div>
      </div>
      {/* Secondary color */}
      <div>
        <label className="label">Secondary Color</label>
        <div className="flex items-center gap-2 mt-1">
          <input type="color" value={style.secondaryColor} onChange={(e) => set("secondaryColor", e.target.value)}
            className="h-8 w-14 rounded cursor-pointer bg-slate-800 border border-slate-700 p-0.5" />
          <span className="text-xs text-slate-400 font-mono">{style.secondaryColor}</span>
        </div>
      </div>
      {/* Evidence box style */}
      <div>
        <label className="label">Evidence Highlight</label>
        <div className="flex gap-2 mt-1 flex-wrap">
          {[["box","Bordered Box"],["shaded","Shaded"],["marker","Marker"],["code","Code Block"]].map(([v, l]) => (
            <button key={v} onClick={() => set("evidenceStyle", v)}
              className={`px-3 py-1 text-xs rounded border transition-colors ${style.evidenceStyle === v ? "border-blue-500 bg-blue-950/50 text-blue-200" : "border-slate-700 text-slate-400"}`}
            >{l}</button>
          ))}
        </div>
      </div>
      {/* Watermark */}
      <div className="sm:col-span-2 lg:col-span-3">
        <label className="label">Watermark text <span className="text-slate-500">(optional)</span></label>
        <input type="text" value={style.watermark} onChange={(e) => set("watermark", e.target.value)}
          placeholder="e.g. CONFIDENTIAL, DRAFT, FOR REVIEW ONLY"
          className="input w-full max-w-md" />
      </div>
    </div>
  );
}

// ─── Panel 4: Extra Info ──────────────────────────────────────────────────────

function ExtraInfoPanel({ extra, onChange }: { extra: ExtraConfig; onChange: (e: ExtraConfig) => void }) {
  const set = (k: keyof ExtraConfig, v: string | string[]) => onChange({ ...extra, [k]: v });
  function toggleMethodology(m: string) {
    const current = extra.methodologies;
    set("methodologies", current.includes(m) ? current.filter((x) => x !== m) : [...current, m]);
  }
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
      <div>
        <label className="label">Classification</label>
        <select value={extra.classification} onChange={(e) => set("classification", e.target.value)} className="input w-full">
          {CLASSIFICATION_LEVELS.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>
      <div>
        <label className="label">Report Version</label>
        <input type="text" value={extra.version} onChange={(e) => set("version", e.target.value)}
          placeholder="1.0" className="input w-full" />
      </div>
      <div>
        <label className="label">Engagement Type</label>
        <select value={extra.engagement_type} onChange={(e) => set("engagement_type", e.target.value)} className="input w-full">
          <option value="black_box">Black Box</option>
          <option value="grey_box">Grey Box</option>
          <option value="white_box">White Box</option>
          <option value="assumed_breach">Assumed Breach</option>
          <option value="purple_team">Purple Team</option>
        </select>
      </div>
      <div className="sm:col-span-2 lg:col-span-3">
        <label className="label">Scope</label>
        <textarea value={extra.scope} onChange={(e) => set("scope", e.target.value)}
          rows={2} placeholder="IPs, domains, applications in scope; explicit exclusions…"
          className="input w-full resize-none" />
      </div>
      <div className="sm:col-span-2">
        <label className="label">Methodology</label>
        <div className="flex flex-wrap gap-2 mt-1">
          {METHODOLOGIES.map((m) => (
            <button key={m} onClick={() => toggleMethodology(m)}
              className={`px-2.5 py-1 text-xs rounded border transition-colors ${extra.methodologies.includes(m) ? "border-blue-500 bg-blue-950/50 text-blue-200" : "border-slate-700 text-slate-400"}`}
            >{m}</button>
          ))}
        </div>
      </div>
      <div>
        <label className="label">Author(s)</label>
        <input type="text" value={extra.authors} onChange={(e) => set("authors", e.target.value)}
          placeholder="John Smith, Jane Doe" className="input w-full" />
      </div>
      <div>
        <label className="label">References <span className="text-slate-500">(tickets, previous reports)</span></label>
        <input type="text" value={extra.references} onChange={(e) => set("references", e.target.value)}
          placeholder="JIRA-1234, RPT-2024-001" className="input w-full" />
      </div>
    </div>
  );
}

// ─── Panel 5: Scans ───────────────────────────────────────────────────────────

interface ScansPanelProps {
  subprojectId: number;
  selectedScanIds: Set<number>;
  onSelectionChange: (ids: Set<number>) => void;
  canImport: boolean;
}

function ScansPanel({ subprojectId, selectedScanIds, onSelectionChange, canImport }: ScansPanelProps) {
  const { data: imports, isLoading } = useScanImports(subprojectId);
  const retry = useRetryScanImport(subprojectId);
  const cancel = useCancelScanImport(subprojectId);
  const [scannerType, setScannerType] = useState("nmap");
  const upload = useUploadScan(subprojectId);
  const qc = useQueryClient();

  // Auto-select newly completed imports
  useEffect(() => {
    if (!imports) return;
    const doneIds = new Set(imports.filter((i) => i.status === "done").map((i) => i.id));
    const updated = new Set([...Array.from(selectedScanIds).filter((id) => doneIds.has(id)), ...Array.from(doneIds)]);
    if (updated.size !== selectedScanIds.size) onSelectionChange(updated);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [imports]);

  function toggleAll() {
    const doneIds = (imports ?? []).filter((i) => i.status === "done").map((i) => i.id);
    const allSelected = doneIds.every((id) => selectedScanIds.has(id));
    onSelectionChange(allSelected ? new Set() : new Set(doneIds));
  }

  function toggleOne(id: number) {
    const next = new Set(selectedScanIds);
    next.has(id) ? next.delete(id) : next.add(id);
    onSelectionChange(next);
  }

  const onDrop = useCallback(async (files: File[]) => {
    if (!canImport) { toast.error("Your license does not allow scan imports."); return; }
    const file = files[0]; if (!file) return;
    const fd = new FormData();
    fd.append("file", file); fd.append("tool", scannerType);
    try {
      await upload.mutateAsync(fd);
      qc.invalidateQueries({ queryKey: ["scanImports", subprojectId] });
      toast.success(`Import started for ${file.name}`);
    } catch { toast.error("Failed to start import."); }
  }, [canImport, scannerType, upload, qc, subprojectId]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop, maxFiles: 1, disabled: !canImport || upload.isPending,
  });

  const done  = (imports ?? []).filter((i) => i.status === "done");
  const allSelected = done.length > 0 && done.every((i) => selectedScanIds.has(i.id));
  const hasActive = (imports ?? []).some((i) => i.status === "pending" || i.status === "processing");

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Left: list */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <p className="text-sm font-medium text-slate-200">
            Scan imports ({imports?.length ?? 0})
            {hasActive && <RefreshCw className="h-3 w-3 inline ml-2 animate-spin text-blue-400" />}
          </p>
          {done.length > 0 && (
            <button onClick={toggleAll} className="text-xs text-blue-400 hover:text-blue-300">
              {allSelected ? "Deselect all" : "Select all"}
            </button>
          )}
        </div>
        {isLoading ? (
          <div className="flex items-center gap-2 py-4 text-slate-500 text-sm"><Loader2 className="h-4 w-4 animate-spin" />Loading…</div>
        ) : !imports?.length ? (
          <p className="text-slate-500 text-sm py-4">No scans imported yet.</p>
        ) : (
          <div className="space-y-1">
            {imports.map((imp) => (
              <div key={imp.id} className={`rounded-lg border px-3 py-2 text-xs transition-colors ${
                imp.status === "done" && selectedScanIds.has(imp.id)
                  ? "border-blue-600/50 bg-blue-950/20"
                  : imp.status === "failed"
                  ? "border-red-900/50"
                  : "border-slate-800"
              }`}>
                <div className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    checked={imp.status === "done" && selectedScanIds.has(imp.id)}
                    onChange={() => imp.status === "done" && toggleOne(imp.id)}
                    disabled={imp.status !== "done"}
                    className="rounded border-slate-600 bg-slate-800 text-blue-500"
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-slate-200 font-medium truncate">{imp.original_filename}</p>
                    <p className="text-slate-500">{imp.tool.toUpperCase()} · {format(new Date(imp.imported_at), "MMM d, HH:mm")}</p>
                  </div>
                  <div className="text-right shrink-0 flex items-center gap-2">
                    {imp.status === "done" && <p className="text-slate-400">{imp.vulnerability_count} findings</p>}
                    <ImportStatusBadge status={imp.status} />
                    {(imp.status === "failed" || imp.status === "processing") && (
                      <button
                        onClick={() => retry.mutate(imp.id, { onSuccess: () => toast.success("Re-queued."), onError: () => toast.error("Retry failed.") })}
                        disabled={retry.isPending || cancel.isPending}
                        className="ml-1 text-slate-400 hover:text-blue-400 transition-colors"
                        title="Retry import"
                      >
                        <RefreshCw className="h-3 w-3" />
                      </button>
                    )}
                    {(imp.status === "pending" || imp.status === "processing") && (
                      <button
                        onClick={() => cancel.mutate(imp.id, { onSuccess: () => toast.success("Import cancelled."), onError: () => toast.error("Cancel failed.") })}
                        disabled={cancel.isPending || retry.isPending}
                        className="ml-1 text-slate-400 hover:text-red-400 transition-colors"
                        title="Cancel import"
                      >
                        {cancel.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <X className="h-3 w-3" />}
                      </button>
                    )}
                  </div>
                </div>
                {imp.status === "failed" && imp.error_message && (
                  <p className="mt-1.5 ml-7 text-red-400 text-xs leading-snug line-clamp-2" title={imp.error_message}>
                    {imp.error_message}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
        {selectedScanIds.size > 0 && (
          <p className="mt-2 text-xs text-blue-400">
            {selectedScanIds.size} scan{selectedScanIds.size > 1 ? "s" : ""} selected for report generation
          </p>
        )}
      </div>

      {/* Right: new import */}
      <div>
        <p className="text-sm font-medium text-slate-200 mb-3">Import new scan</p>
        {!canImport && (
          <div className="rounded-md border border-amber-700 bg-amber-950/50 px-3 py-2 text-xs text-amber-300 mb-3">
            Scan import is disabled on your current plan. <Link to="/settings" className="underline">Upgrade</Link>
          </div>
        )}
        <div className="mb-3">
          <label className="label">Scanner type</label>
          <select value={scannerType} onChange={(e) => setScannerType(e.target.value)} className="input w-full" disabled={!canImport}>
            {SCANNER_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div {...getRootProps()} className={`rounded-lg border-2 border-dashed p-6 text-center cursor-pointer transition-colors ${
          isDragActive ? "border-blue-500 bg-blue-950/30" : canImport ? "border-slate-700 hover:border-slate-500" : "border-slate-800 opacity-50 cursor-not-allowed"
        }`}>
          <input {...getInputProps()} />
          {upload.isPending ? (
            <div className="flex flex-col items-center gap-2 text-slate-400"><Loader2 className="h-6 w-6 animate-spin" /><span className="text-sm">Uploading…</span></div>
          ) : (
            <div className="flex flex-col items-center gap-1 text-slate-500">
              <Upload className="h-6 w-6" />
              <p className="text-sm font-medium">{isDragActive ? "Drop here" : "Drag & drop or click"}</p>
              <p className="text-xs">XML, JSON, CSV · max 50 MB</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Config Toolbar ───────────────────────────────────────────────────────────

interface ToolbarButtonProps { id: PanelId; active: boolean; icon: React.ReactNode; label: string; badge?: string; onClick: () => void; }
function ToolbarButton({ active, icon, label, badge, onClick }: ToolbarButtonProps) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium transition-colors ${
        active ? "border-blue-500 bg-blue-950/60 text-blue-200" : "border-slate-700 hover:border-slate-500 text-slate-400 hover:text-slate-200"
      }`}
    >
      {icon}
      <span className="hidden sm:inline">{label}</span>
      {badge && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-800/60 text-blue-300">{badge}</span>}
      {active ? <ChevronUp className="h-3.5 w-3.5 ml-auto" /> : <ChevronDown className="h-3.5 w-3.5 ml-auto" />}
    </button>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SubProjectPage() {
  const { projectId, id } = useParams<{ projectId: string; id: string }>();
  const pId = Number(projectId);
  const spId = Number(id);
  const navigate = useNavigate();

  const { data: subproject, isLoading } = useSubProject(pId, spId);
  const { data: license } = useLicenseStatus();
  const { data: scanImports } = useScanImports(spId);
  const { data: screenshots } = useScreenshots(pId, spId);
  const { data: exports } = useReportExports(spId);

  const [riskFilter,   setRiskFilter]   = useState<RiskLevel | "">("");
  const [statusFilter, setStatusFilter] = useState<VulnStatus | "">("");

  const hasActiveImports = (scanImports ?? []).some((s) => s.status === "pending" || s.status === "processing");
  const qc = useQueryClient();
  const prevActiveRef = useRef(hasActiveImports);

  // When all imports finish, refresh vulnerabilities
  useEffect(() => {
    if (prevActiveRef.current && !hasActiveImports) {
      qc.invalidateQueries({ queryKey: ["vulnerabilities", spId] });
    }
    prevActiveRef.current = hasActiveImports;
  }, [hasActiveImports, spId, qc]);

  const { data: vulnerabilities, isLoading: vulnLoading } = useVulnerabilities(
    spId,
    {
      ...(riskFilter   ? { risk_level:   riskFilter   } : {}),
      ...(statusFilter ? { vuln_status: statusFilter } : {}),
    },
    { refetchInterval: hasActiveImports ? 3000 : false }
  );

  // ── Report config state ──
  const [activePanel,    setActivePanel]    = useState<PanelId | null>(null);
  const [reportType,     setReportType]     = useState<ReportTypeId | "">("");
  const [audience,       setAudience]       = useState<string[]>(["management","technical"]);
  const [style,          setStyle]          = useState<StyleConfig>(DEFAULT_STYLE);
  const [extra,          setExtra]          = useState<ExtraConfig>(DEFAULT_EXTRA);
  const [selectedScanIds,setSelectedScanIds]= useState<Set<number>>(new Set());

  const RISK_LEVELS: RiskLevel[]  = ["critical","high","medium","low","info"];
  const STATUSES:    VulnStatus[] = ["open","fixed","accepted","retest"];

  function togglePanel(id: PanelId) { setActivePanel((p) => (p === id ? null : id)); }

  const reportTypeLabel   = REPORT_TYPES.find((r) => r.id === reportType)?.label;
  const doneScansCount    = (scanImports ?? []).filter((s) => s.status === "done").length;

  if (isLoading) {
    return (
      <Layout><div className="flex items-center justify-center py-20 text-slate-500"><Loader2 className="h-6 w-6 animate-spin mr-2" />Loading…</div></Layout>
    );
  }
  if (!subproject) {
    return <Layout><p className="text-slate-400 text-center py-20">Sub-project not found.</p></Layout>;
  }

  return (
    <Layout>
      {/* Breadcrumb + back */}
      <div className="flex items-center gap-2 text-sm text-slate-500 mb-4 flex-wrap">
        <button onClick={() => navigate(-1)} className="flex items-center gap-1 hover:text-slate-200 transition-colors">
          <ChevronLeft className="h-3.5 w-3.5" />Back
        </button>
        <span className="text-slate-700">·</span>
        <Link to="/projects" className="hover:text-slate-300">Projects</Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <Link to={`/projects/${pId}`} className="hover:text-slate-300">Project</Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="text-slate-300">{subproject.title}</span>
      </div>

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 mb-5">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">{subproject.title}</h1>
          <p className="text-slate-400 text-sm mt-1">{subproject.scan_date ? format(new Date(subproject.scan_date), "MMMM d, yyyy") : "—"}</p>
          {subproject.description && <p className="text-slate-500 text-sm mt-1">{subproject.description}</p>}
        </div>
        <Link
          to={`/projects/${pId}/reports/builder/${spId}`}
          state={{ reportType, audience, style, extra }}
          className="btn-primary shrink-0"
        >
          <FileText className="h-4 w-4" />Generate Report
        </Link>
      </div>

      {/* Report Config Toolbar */}
      <div className="flex gap-2 flex-wrap mb-3">
        <ToolbarButton id="report_type" active={activePanel === "report_type"} icon={<FileText className="h-4 w-4" />}
          label="Report Type" badge={reportTypeLabel ? reportTypeLabel.split(" ").slice(0, 2).join(" ") : undefined}
          onClick={() => togglePanel("report_type")} />
        <ToolbarButton id="style" active={activePanel === "style"} icon={<Palette className="h-4 w-4" />}
          label="Style" badge={style.font !== "Inter" ? style.font : undefined}
          onClick={() => togglePanel("style")} />
        <ToolbarButton id="extra" active={activePanel === "extra"} icon={<Info className="h-4 w-4" />}
          label="Extra Info" badge={extra.classification !== "CONFIDENTIAL" ? extra.classification : undefined}
          onClick={() => togglePanel("extra")} />
        <ToolbarButton id="scans" active={activePanel === "scans"} icon={<Database className="h-4 w-4" />}
          label="Scans" badge={`${selectedScanIds.size}/${doneScansCount}`}
          onClick={() => togglePanel("scans")} />
      </div>

      {/* Active panel */}
      {activePanel && (
        <div className="card mb-5 border-slate-700/80">
          {activePanel === "report_type" && (
            <ReportTypePanel selectedType={reportType} audience={audience} onTypeChange={setReportType} onAudienceChange={setAudience} />
          )}
          {activePanel === "style" && (
            <StylePanel style={style} onChange={setStyle} />
          )}
          {activePanel === "extra" && (
            <ExtraInfoPanel extra={extra} onChange={setExtra} />
          )}
          {activePanel === "scans" && (
            <ScansPanel subprojectId={spId} selectedScanIds={selectedScanIds} onSelectionChange={setSelectedScanIds} canImport={license?.is_active ?? false} />
          )}
        </div>
      )}

      {/* Main content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Vulnerability table */}
        <div className="lg:col-span-2">
          <div className="card">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
              <h3 className="font-semibold text-slate-100 flex items-center gap-2">
                Vulnerabilities ({vulnerabilities?.length ?? 0})
                {hasActiveImports && <RefreshCw className="h-3.5 w-3.5 animate-spin text-blue-400" />}
              </h3>
              <div className="flex items-center gap-2 flex-wrap">
                <select value={riskFilter} onChange={(e) => setRiskFilter(e.target.value as RiskLevel | "")} className="input py-1 text-xs w-36">
                  <option value="">All Severities</option>
                  {RISK_LEVELS.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
                <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as VulnStatus | "")} className="input py-1 text-xs w-32">
                  <option value="">All Statuses</option>
                  {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
            </div>
            <VulnerabilityTable vulnerabilities={vulnerabilities ?? []} loading={vulnLoading} />
          </div>
        </div>

        {/* Right sidebar */}
        <div className="space-y-4">
          {/* Report exports */}
          <div className="card">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold text-slate-100 flex items-center gap-2 text-sm"><FileText className="h-4 w-4" />Exports</h3>
              <Link to={`/projects/${pId}/reports/builder/${spId}`} state={{ reportType, audience, style, extra }} className="btn-primary text-xs py-1.5"><Plus className="h-3.5 w-3.5" />Generate</Link>
            </div>
            {!exports?.length ? (
              <p className="text-slate-500 text-sm text-center py-3">No reports yet.</p>
            ) : (
              <div className="space-y-2">
                {exports.slice(0, 5).map((exp) => (
                  <div key={exp.id} className="py-1.5 border-b border-slate-800 last:border-0">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        {exp.status === "done"        ? <CheckCircle2 className="h-3.5 w-3.5 text-green-400 shrink-0" />
                         : exp.status === "failed"    ? <AlertCircle  className="h-3.5 w-3.5 text-red-400 shrink-0" />
                         : exp.status === "generating"? <RefreshCw    className="h-3.5 w-3.5 text-blue-400 animate-spin shrink-0" />
                         : <Clock className="h-3.5 w-3.5 text-amber-400 shrink-0" />}
                        <span className="text-xs text-slate-200 font-medium truncate">
                          {exp.report_name || exp.format.toUpperCase()}
                        </span>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          onClick={() => navigate(`/projects/${pId}/reports/builder/${spId}`, {
                            state: {
                              reportType: exp.options.report_type,
                              audience: exp.options.audience ? [exp.options.audience] : undefined,
                              style: exp.options.style,
                              extra: exp.options.extra,
                              enabledCharts: exp.options.charts_enabled,
                              chartVariants: exp.options.charts_variants,
                              sections: exp.options.sections,
                              format: exp.format,
                              risk_levels: exp.options.risk_levels,
                              statuses: exp.options.vuln_status,
                            }
                          })}
                          className="btn-ghost text-xs py-1 text-blue-400 hover:text-blue-300"
                          title="Reopen in builder"
                        >
                          <ExternalLink className="h-3 w-3" />
                        </button>
                        {exp.status === "done" && (
                          <button
                            onClick={() => downloadReport(exp.id, exp.format).catch(() => toast.error("Download failed."))}
                            className="btn-secondary text-xs py-1"
                          >
                            <Download className="h-3 w-3" />
                          </button>
                        )}
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-500 ml-5 mt-0.5">
                      {exp.format.toUpperCase()} · {format(new Date(exp.created_at), "MMM d, HH:mm")}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Screenshots */}
          <div className="card">
            <h3 className="font-semibold text-slate-100 flex items-center gap-2 text-sm mb-3"><Image className="h-4 w-4" />Screenshots ({screenshots?.length ?? 0})</h3>
            <ScreenshotUpload projectId={pId} subprojectId={spId} />
            {screenshots && screenshots.length > 0 && (
              <div className="grid grid-cols-3 gap-2 mt-3">
                {screenshots.slice(0, 6).map((s) => (
                  <a key={s.id} href={s.image} target="_blank" rel="noopener noreferrer"
                    className="rounded overflow-hidden border border-slate-800 hover:border-blue-600 transition-colors">
                    <img src={s.image} alt={s.caption} className="w-full h-16 object-cover" />
                  </a>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}

// ─── Screenshot upload mini-widget ───────────────────────────────────────────

function ScreenshotUpload({ projectId, subprojectId }: { projectId: number; subprojectId: number }) {
  const upload = useUploadScreenshot(projectId, subprojectId);
  const onDrop = useCallback(async (files: File[]) => {
    const file = files[0]; if (!file) return;
    const fd = new FormData(); fd.append("image", file); fd.append("caption", file.name);
    try { await upload.mutateAsync(fd); toast.success("Screenshot uploaded."); }
    catch { toast.error("Failed to upload screenshot."); }
  }, [upload]);
  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop, accept: { "image/*": [] }, maxFiles: 1 });
  return (
    <div {...getRootProps()} className={`rounded-lg border-2 border-dashed p-3 text-center cursor-pointer transition-colors ${isDragActive ? "border-blue-500 bg-blue-950/30" : "border-slate-700 hover:border-slate-500"}`}>
      <input {...getInputProps()} />
      {upload.isPending ? <Loader2 className="h-4 w-4 animate-spin mx-auto text-slate-400" />
        : <p className="text-xs text-slate-500"><Plus className="h-3.5 w-3.5 inline mr-1" />Add screenshot</p>}
    </div>
  );
}

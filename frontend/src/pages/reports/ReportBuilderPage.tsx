/**
 * Report Builder
 *
 * Layout:
 *   Left col (2/3)
 *     1. Audience selector (Executive / Management / Technical)
 *     2. Charts (auto-configured by type+audience, N/A greyed-out)
 *     3. Report Sections (drag-and-drop ordering, enabled by checkbox)
 *     4. Output format
 *     5. Severity & Status filters (only when hasVulns)
 *
 *   Right col (1/3)
 *     1. Section preview (ordered cards, matches left panel)
 *     2. Vuln count summary
 *     3. Generate button
 */
import { useState, useCallback, useRef, useEffect } from "react";
import { useParams, Link, useNavigate, useLocation } from "react-router-dom";
import {
  Loader2, FileText, Download, CheckCircle2, AlertCircle,
  RefreshCw, Clock, ChevronLeft, Eye, GripVertical, Info,
  X, Settings2,
} from "lucide-react";
import toast from "react-hot-toast";
import {
  useVulnerabilities, useGenerateReport, useReportExport, useLicenseStatus, useSubProject,
} from "@/api/hooks";
import { downloadReport } from "@/api/download";
import { Layout } from "@/components/Layout";
import { SeverityBadge } from "@/components/SeverityBadge";
import type { ReportFormat, VulnStatus } from "@/api/types";
import {
  REPORT_SECTIONS, RISK_LEVELS, VULN_STATUSES,
  getDefaultSections, getDefaultChartsForAudience, REPORT_TYPE_CHARTS,
  AUDIENCE_LABELS,
} from "@/constants/reportTypes";
import type { ReportTypeId, AudienceLevel } from "@/constants/reportTypes";

// ─── Charts Configuration ─────────────────────────────────────────────────────

interface ChartDef {
  id: string;
  label: string;
  icon: string;
  desc: string;
  section: string;
  variants: string[];
  defaultVariant: string;
  hasAxes: boolean;
  supports3d: boolean;
}

export interface ChartDetailConfig {
  caption?: string;
  x_axis_label?: string;
  y_axis_label?: string;
  show_legend?: boolean;
  show_grid?: boolean;
  mode_3d?: boolean;
}

const CHARTS: ChartDef[] = [
  { id: "severity_donut",     label: "Severity Distribution", icon: "🍩", desc: "Donut/pie of vuln counts by severity",     section: "Executive", variants: ["Donut","Pie"],           defaultVariant: "Donut",         hasAxes: false, supports3d: false },
  { id: "risk_gauge",         label: "Risk Gauge",            icon: "🎯", desc: "Overall risk score (0–100)",               section: "Executive", variants: ["Gauge","Semaphore"],     defaultVariant: "Gauge",         hasAxes: false, supports3d: false },
  { id: "trend_line",         label: "Historical Trend",      icon: "📈", desc: "Vuln count over time across sub-projects", section: "Executive", variants: ["Line","Area"],           defaultVariant: "Line",          hasAxes: true,  supports3d: false },
  { id: "top_hosts_bar",      label: "Top 5 Exposed Hosts",   icon: "🖥️", desc: "Hosts with most critical vulnerabilities", section: "Executive", variants: ["Horizontal Bar"],        defaultVariant: "Horizontal Bar",hasAxes: true,  supports3d: true  },
  { id: "risk_matrix",        label: "Risk Matrix",           icon: "🗓️", desc: "Likelihood × Impact heatmap",              section: "Results",   variants: ["Heatmap","Bubble"],      defaultVariant: "Heatmap",       hasAxes: true,  supports3d: false },
  { id: "vuln_by_category",   label: "Vulns by Category",     icon: "📊", desc: "Findings grouped by type (OWASP, etc.)",  section: "Results",   variants: ["Bar","Grouped Bar"],     defaultVariant: "Bar",           hasAxes: true,  supports3d: true  },
  { id: "remediation_effort", label: "Remediation Effort",    icon: "🔧", desc: "Estimated effort by severity band",        section: "Results",   variants: ["Stacked Bar"],           defaultVariant: "Stacked Bar",   hasAxes: true,  supports3d: true  },
  { id: "fixed_vs_open",      label: "Fixed vs Open",         icon: "✅", desc: "Remediation progress",                     section: "Results",   variants: ["Donut","Progress Bar"],  defaultVariant: "Donut",         hasAxes: false, supports3d: false },
  { id: "cvss_radar",         label: "CVSS Breakdown",        icon: "🕸️", desc: "CVSS vector components",                  section: "Technical", variants: ["Radar"],                 defaultVariant: "Radar",         hasAxes: false, supports3d: false },
  { id: "epss_distribution",  label: "EPSS Distribution",     icon: "🎲", desc: "Exploit probability distribution",         section: "Technical", variants: ["Histogram","Bar"],       defaultVariant: "Histogram",     hasAxes: true,  supports3d: false },
  { id: "vuln_by_host",       label: "Vulns per Host",        icon: "🔢", desc: "Breakdown of findings per IP/hostname",   section: "Technical", variants: ["Bar","Treemap"],         defaultVariant: "Bar",           hasAxes: true,  supports3d: true  },
];

const DEFAULT_CHARTS_ENABLED: Record<string, boolean> = {
  severity_donut: true, top_hosts_bar: true, risk_matrix: true,
};

// ─── Chart SVG Previews ───────────────────────────────────────────────────────

function ChartPreviewSVG({ variant }: { variant: string }) {
  const v = variant.toLowerCase().replace(/\s+/g, "_");
  const bg = "#0f172a"; const gr = "#334155";
  if (v === "donut") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <circle cx="60" cy="48" r="28" stroke="#dc2626" strokeWidth="13" strokeDasharray="44 132"/>
      <circle cx="60" cy="48" r="28" stroke="#ea580c" strokeWidth="13" strokeDasharray="26 150" strokeDashoffset="-44"/>
      <circle cx="60" cy="48" r="28" stroke="#d97706" strokeWidth="13" strokeDasharray="35 141" strokeDashoffset="-70"/>
      <circle cx="60" cy="48" r="28" stroke="#2563eb" strokeWidth="13" strokeDasharray="27 149" strokeDashoffset="-105"/>
      <circle cx="60" cy="48" r="14" fill={bg}/>
    </svg>
  );
  if (v === "pie") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <path d="M60 48 L60 18 A30 30 0 0 1 90 48 Z" fill="#dc2626"/>
      <path d="M60 48 L90 48 A30 30 0 0 1 48 77 Z" fill="#ea580c"/>
      <path d="M60 48 L48 77 A30 30 0 0 1 30 48 Z" fill="#d97706"/>
      <path d="M60 48 L30 48 A30 30 0 0 1 60 18 Z" fill="#2563eb"/>
    </svg>
  );
  if (v === "horizontal_bar") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <line x1="20" y1="12" x2="20" y2="84" stroke={gr} strokeWidth="1"/>
      <rect x="21" y="15" width="68" height="9" rx="1" fill="#dc2626"/>
      <rect x="21" y="29" width="50" height="9" rx="1" fill="#ea580c"/>
      <rect x="21" y="43" width="60" height="9" rx="1" fill="#d97706"/>
      <rect x="21" y="57" width="38" height="9" rx="1" fill="#2563eb"/>
      <rect x="21" y="71" width="28" height="9" rx="1" fill="#6b7280"/>
    </svg>
  );
  if (v === "bar") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <line x1="15" y1="79" x2="112" y2="79" stroke={gr} strokeWidth="1"/>
      <rect x="20" y="38" width="16" height="41" rx="1" fill="#dc2626"/>
      <rect x="42" y="52" width="16" height="27" rx="1" fill="#ea580c"/>
      <rect x="64" y="43" width="16" height="36" rx="1" fill="#d97706"/>
      <rect x="86" y="60" width="16" height="19" rx="1" fill="#2563eb"/>
    </svg>
  );
  if (v === "grouped_bar") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <line x1="15" y1="79" x2="112" y2="79" stroke={gr} strokeWidth="1"/>
      <rect x="18" y="42" width="9" height="37" rx="1" fill="#dc2626"/>
      <rect x="28" y="55" width="9" height="24" rx="1" fill="#2563eb"/>
      <rect x="44" y="33" width="9" height="46" rx="1" fill="#dc2626"/>
      <rect x="54" y="50" width="9" height="29" rx="1" fill="#2563eb"/>
      <rect x="70" y="50" width="9" height="29" rx="1" fill="#dc2626"/>
      <rect x="80" y="62" width="9" height="17" rx="1" fill="#2563eb"/>
      <rect x="96" y="58" width="9" height="21" rx="1" fill="#dc2626"/>
      <rect x="106" y="68" width="9" height="11" rx="1" fill="#2563eb"/>
    </svg>
  );
  if (v === "stacked_bar") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <line x1="15" y1="79" x2="112" y2="79" stroke={gr} strokeWidth="1"/>
      <rect x="20" y="54" width="16" height="25" rx="1" fill="#dc2626"/>
      <rect x="20" y="40" width="16" height="14" fill="#ea580c"/>
      <rect x="20" y="30" width="16" height="10" fill="#d97706"/>
      <rect x="42" y="45" width="16" height="34" rx="1" fill="#dc2626"/>
      <rect x="42" y="35" width="16" height="10" fill="#ea580c"/>
      <rect x="42" y="27" width="16" height="8" fill="#d97706"/>
      <rect x="64" y="57" width="16" height="22" rx="1" fill="#dc2626"/>
      <rect x="64" y="48" width="16" height="9" fill="#ea580c"/>
      <rect x="86" y="62" width="16" height="17" rx="1" fill="#dc2626"/>
    </svg>
  );
  if (v === "heatmap") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      {([
        [0.9,0.5,0.2,0.1,0.05],
        [0.5,0.7,0.4,0.2,0.1],
        [0.2,0.4,0.6,0.5,0.2],
        [0.05,0.15,0.3,0.7,0.9],
      ] as number[][]).flatMap((row, r) =>
        row.map((val, c) => (
          <rect key={`${r}-${c}`} x={12 + c * 20} y={10 + r * 19} width="18" height="17" rx="1"
            fill={`rgba(220,38,38,${val})`} stroke={bg} strokeWidth="1"/>
        ))
      )}
    </svg>
  );
  if (v === "bubble") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <line x1="15" y1="80" x2="112" y2="80" stroke={gr} strokeWidth="1"/>
      <line x1="15" y1="80" x2="15" y2="10" stroke={gr} strokeWidth="1"/>
      <circle cx="38" cy="55" r="14" fill="#dc262650"/>
      <circle cx="68" cy="38" r="10" fill="#ea580c50"/>
      <circle cx="90" cy="65" r="7" fill="#d9770650"/>
      <circle cx="52" cy="28" r="5" fill="#2563eb50"/>
      <circle cx="104" cy="48" r="8" fill="#dc262650"/>
    </svg>
  );
  if (v === "radar") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <polygon points="60,10 98,33 98,63 60,86 22,63 22,33" stroke={gr} strokeWidth="1" fill="none"/>
      <polygon points="60,24 86,40 86,56 60,72 34,56 34,40" stroke={gr} strokeWidth="1" fill="none"/>
      <polygon points="60,38 74,46 74,50 60,58 46,50 46,46" stroke={gr} strokeWidth="1" fill="none"/>
      <polygon points="60,16 90,38 84,64 54,78 26,57 42,30" stroke="#3b82f6" strokeWidth="1.5" fill="#3b82f620"/>
      <circle cx="60" cy="16" r="2" fill="#3b82f6"/>
      <circle cx="90" cy="38" r="2" fill="#3b82f6"/>
      <circle cx="84" cy="64" r="2" fill="#3b82f6"/>
      <circle cx="54" cy="78" r="2" fill="#3b82f6"/>
      <circle cx="26" cy="57" r="2" fill="#3b82f6"/>
      <circle cx="42" cy="30" r="2" fill="#3b82f6"/>
    </svg>
  );
  if (v === "line" || v === "area") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <line x1="15" y1="80" x2="112" y2="80" stroke={gr} strokeWidth="1"/>
      {v === "area" && <path d="M18,64 L36,50 L54,55 L72,32 L90,42 L108,25 L108,80 L18,80 Z" fill="#dc262618"/>}
      <polyline points="18,64 36,50 54,55 72,32 90,42 108,25" stroke="#dc2626" strokeWidth="2" fill="none"/>
      {[18,36,54,72,90,108].map((x,i) => (
        <circle key={i} cx={x} cy={[64,50,55,32,42,25][i]} r="2.5" fill="#dc2626"/>
      ))}
    </svg>
  );
  if (v === "gauge") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <path d="M18,72 A42,42 0 0 1 102,72" stroke={gr} strokeWidth="12" fill="none" strokeLinecap="round"/>
      <path d="M18,72 A42,42 0 0 1 102,72" stroke="url(#g1)" strokeWidth="12" fill="none" strokeLinecap="round" strokeDasharray="110 132" />
      <defs>
        <linearGradient id="g1" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#22c55e"/>
          <stop offset="50%" stopColor="#d97706"/>
          <stop offset="100%" stopColor="#dc2626"/>
        </linearGradient>
      </defs>
      <line x1="60" y1="72" x2="36" y2="42" stroke="white" strokeWidth="2" strokeLinecap="round"/>
      <circle cx="60" cy="72" r="4" fill="#94a3b8"/>
      <text x="60" y="90" textAnchor="middle" fill="#94a3b8" fontSize="9">72 / 100</text>
    </svg>
  );
  if (v === "semaphore") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <rect x="45" y="8" width="30" height="80" rx="8" fill="#1e293b" stroke="#475569" strokeWidth="1.5"/>
      <circle cx="60" cy="26" r="9" fill="#dc2626"/>
      <circle cx="60" cy="48" r="9" fill="#d97706"/>
      <circle cx="60" cy="70" r="9" fill="#22c55e"/>
    </svg>
  );
  if (v === "histogram") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <line x1="15" y1="79" x2="112" y2="79" stroke={gr} strokeWidth="1"/>
      <rect x="15" y="66" width="14" height="13" fill="#3b82f6"/>
      <rect x="30" y="50" width="14" height="29" fill="#3b82f6"/>
      <rect x="45" y="32" width="14" height="47" fill="#3b82f6"/>
      <rect x="60" y="40" width="14" height="39" fill="#3b82f6"/>
      <rect x="75" y="58" width="14" height="21" fill="#3b82f6"/>
      <rect x="90" y="68" width="14" height="11" fill="#3b82f6"/>
    </svg>
  );
  if (v === "treemap") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <rect x="8" y="8" width="56" height="50" rx="2" fill="#dc262640" stroke="#dc2626" strokeWidth="1"/>
      <rect x="66" y="8" width="46" height="50" rx="2" fill="#ea580c40" stroke="#ea580c" strokeWidth="1"/>
      <rect x="8" y="60" width="40" height="28" rx="2" fill="#d9770640" stroke="#d97706" strokeWidth="1"/>
      <rect x="50" y="60" width="30" height="28" rx="2" fill="#2563eb40" stroke="#2563eb" strokeWidth="1"/>
      <rect x="82" y="60" width="30" height="28" rx="2" fill="#6b728040" stroke="#6b7280" strokeWidth="1"/>
    </svg>
  );
  if (v === "progress_bar") return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <rect x="10" y="22" width="100" height="12" rx="6" fill={gr}/>
      <rect x="10" y="22" width="72" height="12" rx="6" fill="#22c55e"/>
      <text x="10" y="50" fill="#94a3b8" fontSize="8">Fixed 72% · Open 28%</text>
      <rect x="10" y="58" width="100" height="8" rx="4" fill={gr}/>
      <rect x="10" y="58" width="28" height="8" rx="4" fill="#dc2626"/>
      <text x="10" y="80" fill="#94a3b8" fontSize="8">Critical: 28% unresolved</text>
    </svg>
  );
  return (
    <svg viewBox="0 0 120 96" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
      <rect width="120" height="96" fill={bg} rx="4"/>
      <text x="60" y="52" textAnchor="middle" fill="#94a3b8" fontSize="11">{variant}</text>
    </svg>
  );
}

// ─── Chart Detail Panel ───────────────────────────────────────────────────────

function ChartDetailPanel({
  chart, details, currentVariant, onClose, onChange,
}: {
  chart: ChartDef;
  details: ChartDetailConfig;
  currentVariant: string;
  onClose: () => void;
  onChange: (d: ChartDetailConfig) => void;
}) {
  const d = details;
  function set<K extends keyof ChartDetailConfig>(key: K, value: ChartDetailConfig[K]) {
    onChange({ ...d, [key]: value });
  }

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-slate-800 border border-slate-700 rounded-xl w-full max-w-md mx-4 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700">
          <h3 className="font-semibold text-slate-100 flex items-center gap-2">
            <span className="text-lg">{chart.icon}</span>
            {chart.label}
          </h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          {/* Preview */}
          <div className="w-40 h-28 mx-auto rounded-lg overflow-hidden border border-slate-700">
            <ChartPreviewSVG variant={currentVariant} />
          </div>

          {/* Caption / title */}
          <div>
            <label className="label">Chart Caption</label>
            <input
              type="text"
              className="input"
              placeholder={`e.g. "${chart.label}"`}
              value={d.caption ?? ""}
              onChange={(e) => set("caption", e.target.value || undefined)}
            />
          </div>

          {/* Axis labels — only for charts with axes */}
          {chart.hasAxes && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">X Axis Label</label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. Host"
                  value={d.x_axis_label ?? ""}
                  onChange={(e) => set("x_axis_label", e.target.value || undefined)}
                />
              </div>
              <div>
                <label className="label">Y Axis Label</label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. Count"
                  value={d.y_axis_label ?? ""}
                  onChange={(e) => set("y_axis_label", e.target.value || undefined)}
                />
              </div>
            </div>
          )}

          {/* Toggles */}
          <div className="grid grid-cols-3 gap-3">
            {/* Legend */}
            <label className="flex flex-col items-center gap-1.5 cursor-pointer">
              <span className="text-xs text-slate-400">Legend</span>
              <button
                type="button"
                onClick={() => set("show_legend", !(d.show_legend ?? true))}
                className={`w-9 h-5 rounded-full relative transition-colors ${(d.show_legend ?? true) ? "bg-blue-600" : "bg-slate-700"}`}
              >
                <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-transform ${(d.show_legend ?? true) ? "translate-x-4" : "translate-x-0.5"}`} />
              </button>
            </label>

            {/* Grid */}
            {chart.hasAxes && (
              <label className="flex flex-col items-center gap-1.5 cursor-pointer">
                <span className="text-xs text-slate-400">Grid lines</span>
                <button
                  type="button"
                  onClick={() => set("show_grid", !(d.show_grid ?? true))}
                  className={`w-9 h-5 rounded-full relative transition-colors ${(d.show_grid ?? true) ? "bg-blue-600" : "bg-slate-700"}`}
                >
                  <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-transform ${(d.show_grid ?? true) ? "translate-x-4" : "translate-x-0.5"}`} />
                </button>
              </label>
            )}

            {/* 3D */}
            {chart.supports3d && (
              <label className="flex flex-col items-center gap-1.5 cursor-pointer">
                <span className="text-xs text-slate-400">3D mode</span>
                <button
                  type="button"
                  onClick={() => set("mode_3d", !(d.mode_3d ?? false))}
                  className={`w-9 h-5 rounded-full relative transition-colors ${(d.mode_3d ?? false) ? "bg-blue-600" : "bg-slate-700"}`}
                >
                  <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-transform ${(d.mode_3d ?? false) ? "translate-x-4" : "translate-x-0.5"}`} />
                </button>
              </label>
            )}
          </div>
        </div>

        <div className="px-5 py-3 border-t border-slate-700 flex justify-end">
          <button onClick={onClose} className="btn-primary text-sm px-4 py-1.5">Done</button>
        </div>
      </div>
    </div>
  );
}

// ─── ChartsPanel ──────────────────────────────────────────────────────────────

interface ChartsPanelProps {
  enabledCharts: Record<string, boolean>;
  chartVariants: Record<string, string>;
  chartDetails: Record<string, ChartDetailConfig>;
  reportType: ReportTypeId | "";
  audience: AudienceLevel;
  onToggle: (id: string) => void;
  onVariant: (id: string, v: string) => void;
  onUpdateDetails: (id: string, d: ChartDetailConfig) => void;
}

function ChartsPanel({ enabledCharts, chartVariants, chartDetails, reportType, audience, onToggle, onVariant, onUpdateDetails }: ChartsPanelProps) {
  const sections = Array.from(new Set(CHARTS.map((c) => c.section)));
  const hoverTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [previewId, setPreviewId] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);

  // Per-chart config from the spec mapping (if available for this report type)
  const typeConfig = reportType ? (REPORT_TYPE_CHARTS[reportType as ReportTypeId] ?? null) : null;

  function startHover(id: string) {
    hoverTimer.current = setTimeout(() => setPreviewId(id), 2000);
  }
  function endHover() {
    if (hoverTimer.current) clearTimeout(hoverTimer.current);
    setPreviewId(null);
  }

  const editingChart = editingId ? CHARTS.find((c) => c.id === editingId) ?? null : null;

  return (
    <>
      <div className="space-y-5">
        {sections.map((sec) => (
          <div key={sec}>
            <p className="text-xs text-slate-500 uppercase tracking-wider font-medium mb-2">{sec} Charts</p>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {CHARTS.filter((c) => c.section === sec).map((chart) => {
                const chartCfg = typeConfig?.[chart.id];
                const isNotApplicable = chartCfg?.notApplicable === true;
                const enabled = !isNotApplicable && (enabledCharts[chart.id] ?? false);
                const variant = chartVariants[chart.id] ?? chart.defaultVariant;
                const showPreview = previewId === chart.id;

                // Audience hint: show which audiences can use this chart (only when a type is selected)
                const audienceHint: string | null = (() => {
                  if (!typeConfig || !chartCfg || isNotApplicable) return null;
                  const ef = chartCfg.enabledFor;
                  if (ef.length === 3) return null; // all audiences — no hint needed
                  if (ef.length === 0) return null;  // off by default — no specific restriction
                  if (ef.length === 1) return ef[0]!.charAt(0).toUpperCase() + ef[0]!.slice(1) + " only";
                  if (ef.length === 2) {
                    const notIn = (["executive","management","technical"] as AudienceLevel[]).find((a) => !ef.includes(a));
                    return notIn ? `Not for ${notIn}` : null;
                  }
                  return null;
                })();

                return (
                  <div
                    key={chart.id}
                    className={`relative rounded-lg border px-3 py-2.5 transition-colors ${
                      isNotApplicable
                        ? "border-slate-800 opacity-40 cursor-not-allowed"
                        : enabled
                          ? "border-blue-600/70 bg-blue-950/30"
                          : "border-slate-700"
                    }`}
                  >
                    {/* Hover preview tooltip */}
                    {showPreview && !isNotApplicable && (
                      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 z-30 pointer-events-none">
                        <div className="bg-slate-900 border border-slate-600 rounded-lg shadow-2xl p-2 w-36">
                          <div className="w-full h-24 rounded overflow-hidden">
                            <ChartPreviewSVG variant={variant} />
                          </div>
                          <p className="text-[10px] text-slate-400 text-center mt-1">{variant}</p>
                        </div>
                        <div className="w-2 h-2 bg-slate-900 border-b border-r border-slate-600 rotate-45 mx-auto -mt-1" />
                      </div>
                    )}

                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        {/* Label — hover triggers preview, click opens detail editor */}
                        <div
                          className={`flex items-center gap-1.5 group ${isNotApplicable ? "cursor-not-allowed" : "cursor-pointer"}`}
                          onMouseEnter={() => !isNotApplicable && startHover(chart.id)}
                          onMouseLeave={endHover}
                          onClick={() => { if (!isNotApplicable) { endHover(); setEditingId(chart.id); } }}
                          title={isNotApplicable ? "Not applicable for this report type" : "Click to configure chart details"}
                        >
                          <span className="text-base">{chart.icon}</span>
                          <span className={`text-xs font-medium ${isNotApplicable ? "text-slate-600" : enabled ? "text-blue-200 group-hover:underline decoration-dotted" : "text-slate-300 group-hover:underline decoration-dotted"}`}>
                            {chart.label}
                          </span>
                          {!isNotApplicable && <Settings2 className="h-3 w-3 text-slate-600 group-hover:text-slate-400 shrink-0" />}
                          {isNotApplicable && <span className="text-[9px] font-semibold text-slate-600 bg-slate-800 rounded px-1 py-0.5 ml-0.5">N/A</span>}
                        </div>
                        <p className="text-[11px] text-slate-500 mt-0.5">{chart.desc}</p>
                        {audienceHint && !enabled && (
                          <p className="text-[10px] text-amber-600/80 mt-0.5">{audienceHint}</p>
                        )}
                      </div>
                      <button
                        onClick={() => !isNotApplicable && onToggle(chart.id)}
                        disabled={isNotApplicable}
                        className={`mt-0.5 w-8 h-4 rounded-full relative transition-colors shrink-0 ${isNotApplicable ? "bg-slate-800 cursor-not-allowed" : enabled ? "bg-blue-600" : "bg-slate-700"}`}
                        aria-label={isNotApplicable ? "Not applicable" : enabled ? "Disable chart" : "Enable chart"}
                      >
                        <span className={`absolute top-0.5 w-3 h-3 bg-white rounded-full transition-transform ${enabled ? "translate-x-4" : "translate-x-0.5"}`} />
                      </button>
                    </div>
                    {enabled && chart.variants.length > 1 && (
                      <select
                        value={variant}
                        onChange={(e) => onVariant(chart.id, e.target.value)}
                        className="mt-2 input py-0.5 text-xs w-full"
                      >
                        {chart.variants.map((v) => <option key={v} value={v}>{v}</option>)}
                      </select>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Detail editor modal */}
      {editingChart && (
        <ChartDetailPanel
          chart={editingChart}
          details={chartDetails[editingChart.id] ?? {}}
          currentVariant={chartVariants[editingChart.id] ?? editingChart.defaultVariant}
          onClose={() => setEditingId(null)}
          onChange={(d) => onUpdateDetails(editingChart.id, d)}
        />
      )}
    </>
  );
}

// ─── Export status watcher ───────────────────────────────────────────────────

function ExportStatusCard({ exportId }: { exportId: number }) {
  const { data: exp } = useReportExport(exportId);
  const [downloading, setDownloading] = useState(false);

  if (!exp) return null;

  async function handleDownload() {
    setDownloading(true);
    try {
      await downloadReport(exportId, exp!.format);
    } catch {
      toast.error("Download failed. Please try again.");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <div className={`card border ${exp.status === "done" ? "border-green-700" : exp.status === "failed" ? "border-red-700" : "border-slate-700"}`}>
      <div className="flex items-center gap-3">
        {exp.status === "pending"    && <Clock     className="h-5 w-5 text-amber-400" />}
        {exp.status === "generating" && <RefreshCw className="h-5 w-5 text-blue-400 animate-spin" />}
        {exp.status === "done"       && <CheckCircle2 className="h-5 w-5 text-green-400" />}
        {exp.status === "failed"     && <AlertCircle  className="h-5 w-5 text-red-400" />}
        <div className="flex-1">
          <p className="font-medium text-slate-100">
            {exp.status === "pending" && "Report queued…"}
            {exp.status === "generating" && "Generating report…"}
            {exp.status === "done" && "Report ready!"}
            {exp.status === "failed" && "Generation failed"}
          </p>
          {exp.status === "failed" && exp.error_message && (
            <p className="text-sm text-red-400 mt-1">{exp.error_message}</p>
          )}
          {(exp.status === "pending" || exp.status === "generating") && (
            <p className="text-sm text-slate-500 mt-1">This may take a minute. The page will update automatically.</p>
          )}
        </div>
        {exp.status === "done" && (
          <button onClick={handleDownload} disabled={downloading} className="btn-primary shrink-0">
            {downloading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            {downloading ? "Downloading…" : `Download ${exp.format.toUpperCase()}`}
          </button>
        )}
      </div>
    </div>
  );
}

// ─── Section drag-and-drop list ───────────────────────────────────────────────

interface SectionListProps {
  orderedIds: string[];
  enabledIds: Set<string>;
  onReorder: (ids: string[]) => void;
  onToggle: (id: string) => void;
}

function SectionList({ orderedIds, enabledIds, onReorder, onToggle }: SectionListProps) {
  const dragIndex = useRef<number | null>(null);

  function handleDragStart(i: number) { dragIndex.current = i; }

  function handleDragOver(e: React.DragEvent, i: number) {
    e.preventDefault();
    if (dragIndex.current === null || dragIndex.current === i) return;
    const next = [...orderedIds];
    const [removed] = next.splice(dragIndex.current, 1);
    next.splice(i, 0, removed);
    dragIndex.current = i;
    onReorder(next);
  }

  const sections = orderedIds.map((id) => REPORT_SECTIONS.find((s) => s.id === id)!).filter(Boolean);

  return (
    <div className="space-y-1.5">
      {sections.map((sec, i) => {
        const enabled = enabledIds.has(sec.id);
        const required = sec.required;
        return (
          <div
            key={sec.id}
            draggable={!required}
            onDragStart={() => handleDragStart(i)}
            onDragOver={(e) => handleDragOver(e, i)}
            className={`flex items-center gap-3 rounded-lg border px-3 py-2.5 transition-colors select-none ${
              enabled ? "border-blue-600/50 bg-blue-950/20" : "border-slate-800 opacity-50"
            } ${!required ? "cursor-grab active:cursor-grabbing" : ""}`}
          >
            {required ? (
              <span className="text-slate-600 w-4 h-4 shrink-0" />
            ) : (
              <GripVertical className="h-4 w-4 text-slate-600 shrink-0" />
            )}
            <input
              type="checkbox"
              checked={enabled}
              disabled={required}
              onChange={() => !required && onToggle(sec.id)}
              className="rounded border-slate-600 bg-slate-800 text-blue-500 shrink-0"
            />
            <span className="text-base shrink-0">{sec.icon}</span>
            <div className="flex-1 min-w-0">
              <p className={`text-sm font-medium ${enabled ? "text-slate-100" : "text-slate-500"}`}>
                {sec.label}
                {required && <span className="ml-1.5 text-[10px] text-slate-600 font-normal">(required)</span>}
              </p>
              <p className="text-xs text-slate-600 truncate">{sec.desc}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Section preview (right sidebar) ─────────────────────────────────────────

function SectionPreview({ orderedIds, enabledIds }: { orderedIds: string[]; enabledIds: Set<string> }) {
  const visible = orderedIds
    .filter((id) => enabledIds.has(id))
    .map((id) => REPORT_SECTIONS.find((s) => s.id === id)!)
    .filter(Boolean);

  return (
    <div className="card">
      <h3 className="font-semibold text-slate-100 mb-3 text-sm flex items-center gap-2">
        <Eye className="h-4 w-4" />Report Structure Preview
      </h3>
      <div className="space-y-1">
        {visible.map((sec, i) => (
          <div key={sec.id} className="flex items-center gap-2 py-1 border-b border-slate-800/60 last:border-0">
            <span className="text-xs text-slate-600 w-4 text-right shrink-0">{i + 1}</span>
            <span className="text-sm shrink-0">{sec.icon}</span>
            <span className="text-xs text-slate-300 truncate">{sec.label}</span>
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-600 mt-3">{visible.length} section{visible.length !== 1 ? "s" : ""} · drag to reorder</p>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

const FORMATS: { value: ReportFormat; label: string; desc: string }[] = [
  { value: "pdf",  label: "PDF",  desc: "Professional printable via WeasyPrint" },
  { value: "html", label: "HTML", desc: "Standalone with embedded assets" },
  { value: "xml",  label: "XML",  desc: "Structured data for interoperability" },
];

// Config passed from SubProjectPage or from export-reopen.
interface IncomingConfig {
  reportType?: ReportTypeId;
  audience?: string | string[];
  style?: Record<string, string>;
  extra?: Record<string, unknown>;
  // From export-reopen or charts section
  enabledCharts?: Record<string, boolean>;
  chartVariants?: Record<string, string>;
  sections?: string[];
  format?: ReportFormat;
  risk_levels?: string[];
  statuses?: VulnStatus[];
}

/**
 * Collapse the audience array (e.g. ["management","technical"]) to the single
 * least-restrictive value so the template knows what to show.
 * "technical" > "management" > "executive"
 */
function collapseAudience(arr: string[] | undefined): string {
  if (!arr || arr.length === 0) return "technical";
  if (arr.includes("technical")) return "technical";
  if (arr.includes("management")) return "management";
  return "executive";
}

function initFromConfig(config: IncomingConfig | undefined): {
  reportType: ReportTypeId | "";
  orderedSections: string[];
  enabledSections: Set<string>;
  enabledCharts: Record<string, boolean>;
  chartVariants: Record<string, string>;
} {
  // When reopening from an export: use stored sections and charts
  if (config?.sections && config.sections.length > 0) {
    const allIds = REPORT_SECTIONS.map((s) => s.id);
    const stored = config.sections;
    const sorted = [...stored, ...allIds.filter((id) => !stored.includes(id))];
    return {
      reportType: (config.reportType as ReportTypeId) || "",
      orderedSections: sorted,
      enabledSections: new Set([...stored, ...REPORT_SECTIONS.filter((s) => s.required).map((s) => s.id)]),
      enabledCharts: config.enabledCharts ?? DEFAULT_CHARTS_ENABLED,
      chartVariants: config.chartVariants ?? {},
    };
  }
  if (config?.reportType) {
    const defaults = getDefaultSections(config.reportType);
    const allIds = REPORT_SECTIONS.map((s) => s.id);
    const sorted = [...defaults, ...allIds.filter((id) => !defaults.includes(id))];
    return {
      reportType: config.reportType,
      orderedSections: sorted,
      enabledSections: new Set([...defaults, ...REPORT_SECTIONS.filter((s) => s.required).map((s) => s.id)]),
      enabledCharts: config.enabledCharts ?? DEFAULT_CHARTS_ENABLED,
      chartVariants: config.chartVariants ?? {},
    };
  }
  return {
    reportType: "",
    orderedSections: REPORT_SECTIONS.map((s) => s.id),
    enabledSections: new Set(REPORT_SECTIONS.map((s) => s.id)),
    enabledCharts: config?.enabledCharts ?? DEFAULT_CHARTS_ENABLED,
    chartVariants: config?.chartVariants ?? {},
  };
}

export default function ReportBuilderPage() {
  const { subprojectId, projectId } = useParams<{ subprojectId: string; projectId?: string }>();
  const spId = Number(subprojectId);
  const pId = Number(projectId ?? 0);
  const navigate = useNavigate();
  const location = useLocation();
  const incoming = (location.state ?? undefined) as IncomingConfig | undefined;

  const { data: subproject } = useSubProject(pId, spId);
  const { data: vulns } = useVulnerabilities(spId);
  const { data: license } = useLicenseStatus();
  const generateReport = useGenerateReport();

  // ── State — seeded from SubProjectPage config or export-reopen ──
  const [format, setFormat] = useState<ReportFormat>(incoming?.format ?? "pdf");

  const init = initFromConfig(incoming);
  const [reportType, setReportType] = useState<ReportTypeId | "">(init.reportType);
  const [orderedSections, setOrderedSections] = useState<string[]>(init.orderedSections);
  const [enabledSections, setEnabledSections] = useState<Set<string>>(init.enabledSections);
  const [selectedRiskLevels, setSelectedRiskLevels] = useState<string[]>(
    incoming?.risk_levels ?? [...RISK_LEVELS]
  );
  const [selectedStatuses, setSelectedStatuses] = useState<string[]>(
    incoming?.statuses ?? ["open", "retest"]
  );
  const [enabledCharts, setEnabledCharts] = useState<Record<string, boolean>>(init.enabledCharts);
  const [chartVariants, setChartVariants] = useState<Record<string, string>>(init.chartVariants);
  const [chartDetails, setChartDetails] = useState<Record<string, ChartDetailConfig>>({});

  const [audience, setAudience] = useState<AudienceLevel>(
    collapseAudience(
      Array.isArray(incoming?.audience) ? incoming.audience : incoming?.audience ? [incoming.audience] : undefined
    ) as AudienceLevel
  );
  const rptStyle = incoming?.style ?? undefined;
  const rptExtra = incoming?.extra ?? undefined;
  const [generatedExportId, setGeneratedExportId] = useState<number | null>(null);

  // Auto-configure charts whenever report type or audience changes
  useEffect(() => {
    if (!reportType) return;
    setEnabledCharts(getDefaultChartsForAudience(reportType, audience));
  }, [reportType, audience]);

  function toggleChart(id: string) {
    setEnabledCharts((prev) => ({ ...prev, [id]: !prev[id] }));
  }
  function setChartVariant(id: string, v: string) {
    setChartVariants((prev) => ({ ...prev, [id]: v }));
  }
  function updateChartDetails(id: string, d: ChartDetailConfig) {
    setChartDetails((prev) => ({ ...prev, [id]: d }));
  }

  const canExport = license?.is_active ?? false;

  const enabledChartCount = Object.values(enabledCharts).filter(Boolean).length;

  // Filter preview
  const filteredVulns = (vulns ?? []).filter(
    (v) => selectedRiskLevels.includes(v.risk_level) && selectedStatuses.includes(v.vuln_status)
  );

  const canGenerate = canExport && filteredVulns.length > 0 && enabledSections.size > 0;

  // ── Handlers ──
  function toggleSection(id: string) {
    setEnabledSections((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function toggleRiskLevel(level: string) {
    setSelectedRiskLevels((prev) => prev.includes(level) ? prev.filter((l) => l !== level) : [...prev, level]);
  }

  function toggleStatus(status: string) {
    setSelectedStatuses((prev) => prev.includes(status) ? prev.filter((s) => s !== status) : [...prev, status]);
  }

  const handleReorder = useCallback((ids: string[]) => setOrderedSections(ids), []);

  async function handleGenerate() {
    if (!canExport) { toast.error("Report export is disabled on your current plan."); return; }
    if (filteredVulns.length === 0) { toast.error("No vulnerabilities match the selected filters."); return; }
    if (enabledSections.size === 0) { toast.error("Select at least one report section."); return; }
    try {
      const activeCharts = Object.fromEntries(
        Object.entries(enabledCharts).filter(([, v]) => v)
      );
      const result = await generateReport.mutateAsync({
        subproject: spId,
        format,
        risk_levels: selectedRiskLevels,
        statuses: selectedStatuses,
        report_type: reportType || undefined,
        sections: orderedSections.filter((id) => enabledSections.has(id)),
        audience,
        ...(rptStyle              ? { style: rptStyle }                  : {}),
        ...(rptExtra              ? { extra: rptExtra }                  : {}),
        ...(Object.keys(activeCharts).length > 0 ? { charts_enabled: activeCharts } : {}),
        ...(Object.keys(chartVariants).length > 0 ? { charts_variants: chartVariants } : {}),
        ...(Object.keys(chartDetails).length > 0 ? { charts_details: chartDetails } : {}),
      });
      setGeneratedExportId(result.id);
      toast.success("Report generation started!");
    } catch {
      toast.error("Failed to start report generation.");
    }
  }

  const countByLevel = (level: string) => filteredVulns.filter((v) => v.risk_level === level).length;

  return (
    <Layout>
      {/* Navigation */}
      <div className="flex items-center gap-3 mb-5">
        <button onClick={() => navigate(-1)} className="flex items-center gap-1.5 text-slate-400 hover:text-slate-200 text-sm transition-colors">
          <ChevronLeft className="h-4 w-4" />Back
        </button>
        <span className="text-slate-700">·</span>
        <Link to="/projects" className="text-slate-500 hover:text-slate-300 text-sm">Projects</Link>
        {subproject && (
          <>
            <span className="text-slate-700">·</span>
            <Link to={`/projects/${subproject.project}/subprojects/${spId}`} className="text-slate-500 hover:text-slate-300 text-sm truncate max-w-xs">
              {subproject.title}
            </Link>
          </>
        )}
        <span className="text-slate-700">·</span>
        <span className="text-slate-300 text-sm">Report Builder</span>
      </div>

      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Report Builder</h1>
          <p className="text-slate-400 text-sm mt-1">
            {subproject ? subproject.title : `Sub-project #${spId}`}
          </p>
        </div>
        <FileText className="h-8 w-8 text-slate-600" />
      </div>

      {!canExport && (
        <div className="rounded-md border border-amber-700 bg-amber-950/50 px-4 py-3 text-sm text-amber-300 mb-6">
          Report export is not available on your current plan.{" "}
          <Link to="/settings" className="underline font-medium">Upgrade to PRO</Link> to generate reports.
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ── Left column ── */}
        <div className="lg:col-span-2 space-y-5">

          {/* 1. Audience selector */}
          <div className="card">
            <h3 className="font-semibold text-slate-100 mb-3">Audience</h3>
            <p className="text-xs text-slate-500 mb-3">
              Selects the appropriate charts and level of detail for the report.
            </p>
            <div className="flex gap-2">
              {(Object.entries(AUDIENCE_LABELS) as [AudienceLevel, string][]).map(([key, label]) => (
                <button
                  key={key}
                  onClick={() => setAudience(key)}
                  className={`flex-1 rounded-lg border px-3 py-2 text-left transition-colors ${
                    audience === key
                      ? "border-blue-500 bg-blue-950/40 text-slate-100"
                      : "border-slate-700 text-slate-400 hover:border-slate-500 hover:text-slate-300"
                  }`}
                >
                  <p className="text-xs font-semibold">{
                    key === "executive" ? "Executive" : key === "management" ? "Management" : "Technical"
                  }</p>
                  <p className="text-[10px] text-slate-500 mt-0.5 leading-tight">{label}</p>
                </button>
              ))}
            </div>
          </div>

          {/* 2. Charts */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-slate-100">Charts</h3>
              <span className="text-xs text-slate-500">{enabledChartCount} active</span>
            </div>
            <ChartsPanel
              enabledCharts={enabledCharts}
              chartVariants={chartVariants}
              chartDetails={chartDetails}
              reportType={reportType}
              audience={audience}
              onToggle={toggleChart}
              onVariant={setChartVariant}
              onUpdateDetails={updateChartDetails}
            />
            <div className="flex items-center gap-2 mt-3 text-xs text-slate-500">
              <Info className="h-3.5 w-3.5 shrink-0" />
              Charts are embedded as images in PDF and HTML exports. Toggle and configure each chart below.
            </div>
          </div>

          {/* 3. Report sections */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-slate-100">Report Sections</h3>
              <span className="text-xs text-slate-500">{enabledSections.size} selected · drag to reorder</span>
            </div>
            <SectionList
              orderedIds={orderedSections}
              enabledIds={enabledSections}
              onReorder={handleReorder}
              onToggle={toggleSection}
            />
          </div>

          {/* 4. Output format */}
          <div className="card">
            <h3 className="font-semibold text-slate-100 mb-4">Output Format</h3>
            <div className="grid grid-cols-3 gap-3">
              {FORMATS.map((f) => (
                <button key={f.value} onClick={() => setFormat(f.value)}
                  className={`rounded-lg border p-4 text-left transition-colors ${format === f.value ? "border-blue-500 bg-blue-950/40" : "border-slate-700 hover:border-slate-500"}`}
                >
                  <p className="font-semibold text-slate-100 text-sm">{f.label}</p>
                  <p className="text-xs text-slate-500 mt-1">{f.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* 5. Severity & status filters */}
          <>
            <div className="card">
                <h3 className="font-semibold text-slate-100 mb-4">Include Severities</h3>
                <div className="flex flex-wrap gap-2">
                  {RISK_LEVELS.map((level) => {
                    const cnt = (vulns ?? []).filter((v) => v.risk_level === level).length;
                    const sel = selectedRiskLevels.includes(level);
                    return (
                      <button key={level} onClick={() => toggleRiskLevel(level)}
                        className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm transition-colors ${sel ? "border-transparent" : "border-slate-700 opacity-40"}`}
                      >
                        <SeverityBadge level={level} />
                        <span className={`text-xs font-medium ${sel ? "text-slate-200" : "text-slate-500"}`}>({cnt})</span>
                        {sel && <span className="text-xs text-green-400">✓</span>}
                      </button>
                    );
                  })}
                </div>
                <div className="flex gap-2 mt-3">
                  <button onClick={() => setSelectedRiskLevels([...RISK_LEVELS])} className="text-xs text-blue-400 hover:text-blue-300">Select all</button>
                  <span className="text-slate-600">·</span>
                  <button onClick={() => setSelectedRiskLevels([])} className="text-xs text-slate-400 hover:text-slate-200">Clear all</button>
                </div>
              </div>

              <div className="card">
                <h3 className="font-semibold text-slate-100 mb-4">Include Statuses</h3>
                <div className="flex flex-wrap gap-2">
                  {VULN_STATUSES.map((status) => {
                    const cnt = (vulns ?? []).filter((v) => v.vuln_status === status && selectedRiskLevels.includes(v.risk_level)).length;
                    const sel = selectedStatuses.includes(status);
                    return (
                      <button key={status} onClick={() => toggleStatus(status)}
                        className={`rounded-full border px-3 py-1.5 text-sm font-medium transition-colors capitalize ${sel ? "bg-slate-700 border-slate-500 text-slate-100" : "border-slate-700 text-slate-500 hover:border-slate-500"}`}
                      >
                        {status} ({cnt})
                      </button>
                    );
                  })}
                </div>
              </div>
          </>

          {/* Export result */}
          {generatedExportId && <ExportStatusCard exportId={generatedExportId} />}
        </div>

        {/* ── Right column ── */}
        <div className="space-y-4">
          {/* Section preview */}
          <SectionPreview orderedIds={orderedSections} enabledIds={enabledSections} />

          {/* Vuln summary */}
          <div className="card">
              <h3 className="font-semibold text-slate-100 mb-3 text-sm">Vulnerability Summary</h3>
              <div className="space-y-1.5">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-500">Total matching</span>
                  <span className="text-slate-200 font-medium">{filteredVulns.length}</span>
                </div>
                {RISK_LEVELS.map((level) => {
                  const c = countByLevel(level);
                  if (c === 0) return null;
                  return (
                    <div key={level} className="flex justify-between items-center text-xs">
                      <span className="text-slate-500 pl-3">{level.charAt(0).toUpperCase() + level.slice(1)}</span>
                      <SeverityBadge level={level} />
                    </div>
                  );
                })}
                {filteredVulns.length === 0 && (
                  <p className="text-xs text-amber-400 mt-1">No vulnerabilities match the current filters.</p>
                )}
              </div>
            </div>

          {/* Generate card */}
          <div className="card sticky top-6">
            <h3 className="font-semibold text-slate-100 mb-4">Generate Report</h3>
            <div className="space-y-2 mb-4 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-500">Format</span>
                <span className="text-slate-200 font-medium uppercase">{format}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Charts</span>
                <span className="text-slate-200 font-medium">{enabledChartCount}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Sections</span>
                <span className="text-slate-200 font-medium">{enabledSections.size}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Vulnerabilities</span>
                <span className="text-slate-200 font-medium">{filteredVulns.length}</span>
              </div>
            </div>
            <button
              onClick={handleGenerate}
              disabled={!canGenerate || generateReport.isPending}
              className="btn-primary w-full"
            >
              {generateReport.isPending ? (
                <><Loader2 className="h-4 w-4 animate-spin" />Starting…</>
              ) : (
                <><FileText className="h-4 w-4" />Generate {format.toUpperCase()}</>
              )}
            </button>
            {!canExport && (
              <p className="text-xs text-amber-400 mt-2 text-center">Upgrade to PRO to export reports.</p>
            )}
            {canExport && filteredVulns.length === 0 && (
              <p className="text-xs text-amber-400 mt-2 text-center">No vulnerabilities match the filters.</p>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}

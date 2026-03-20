/**
 * Report Builder
 *
 * Layout:
 *   Left col (2/3)
 *     1. Report Type selector (grid by category)
 *     2. Report Sections (drag-and-drop ordering, enabled by checkbox)
 *     3. Output format
 *     4. Severity & Status filters (only when hasVulns)
 *
 *   Right col (1/3)
 *     1. Section preview (ordered cards, matches left panel)
 *     2. Vuln count summary
 *     3. Generate button
 */
import { useState, useCallback, useRef } from "react";
import { useParams, Link, useNavigate, useLocation } from "react-router-dom";
import {
  Loader2, FileText, Download, CheckCircle2, AlertCircle,
  RefreshCw, Clock, ChevronLeft, Eye, GripVertical, Info,
} from "lucide-react";
import toast from "react-hot-toast";
import {
  useVulnerabilities, useGenerateReport, useReportExport, useLicenseStatus, useSubProject,
} from "@/api/hooks";
import { downloadReport } from "@/api/download";
import { Layout } from "@/components/Layout";
import { SeverityBadge } from "@/components/SeverityBadge";
import type { ReportFormat } from "@/api/types";
import {
  REPORT_TYPES, REPORT_SECTIONS, RISK_LEVELS, VULN_STATUSES,
  getDefaultSections,
} from "@/constants/reportTypes";
import type { ReportTypeId } from "@/constants/reportTypes";

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

// Config passed from SubProjectPage via router state.
interface IncomingConfig {
  reportType?: ReportTypeId;
  audience?: string[];
  style?: Record<string, string>;
  extra?: Record<string, unknown>;
  enabledCharts?: Record<string, boolean>;
  chartVariants?: Record<string, string>;
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
} {
  if (config?.reportType) {
    const defaults = getDefaultSections(config.reportType);
    const allIds = REPORT_SECTIONS.map((s) => s.id);
    const sorted = [...defaults, ...allIds.filter((id) => !defaults.includes(id))];
    return {
      reportType: config.reportType,
      orderedSections: sorted,
      enabledSections: new Set([...defaults, ...REPORT_SECTIONS.filter((s) => s.required).map((s) => s.id)]),
    };
  }
  return {
    reportType: "",
    orderedSections: REPORT_SECTIONS.map((s) => s.id),
    enabledSections: new Set(REPORT_SECTIONS.map((s) => s.id)),
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

  // ── State — seeded from SubProjectPage config if available ──
  const [format, setFormat] = useState<ReportFormat>("pdf");

  const init = initFromConfig(incoming);
  const [reportType, setReportType] = useState<ReportTypeId | "">(init.reportType);
  const [orderedSections, setOrderedSections] = useState<string[]>(init.orderedSections);
  const [enabledSections, setEnabledSections] = useState<Set<string>>(init.enabledSections);
  const [selectedRiskLevels, setSelectedRiskLevels] = useState<string[]>([...RISK_LEVELS]);
  const [selectedStatuses, setSelectedStatuses] = useState<string[]>(["open", "retest"]);

  // Opaque config forwarded verbatim from SubProjectPage — no UI in Builder.
  const rptAudience = collapseAudience(incoming?.audience);
  const rptStyle = incoming?.style ?? undefined;
  const rptExtra = incoming?.extra ?? undefined;
  const rptChartsEnabled = incoming?.enabledCharts ?? undefined;
  const rptChartsVariants = incoming?.chartVariants ?? undefined;
  const [generatedExportId, setGeneratedExportId] = useState<number | null>(null);

  const canExport = license?.is_active ?? false;

  const selectedTypeInfo = REPORT_TYPES.find((r) => r.id === reportType);
  const needsVulns = selectedTypeInfo ? selectedTypeInfo.hasVulns : true;

  // Filter preview
  const filteredVulns = (vulns ?? []).filter(
    (v) => selectedRiskLevels.includes(v.risk_level) && selectedStatuses.includes(v.vuln_status)
  );

  const canGenerate = canExport && (!needsVulns || filteredVulns.length > 0) && enabledSections.size > 0;

  // ── Handlers ──
  function selectReportType(id: ReportTypeId) {
    setReportType(id);
    const defaults = getDefaultSections(id);
    const allIds = REPORT_SECTIONS.map((s) => s.id);
    // Put defaults first, then the rest
    const sorted = [...defaults, ...allIds.filter((sid) => !defaults.includes(sid))];
    setOrderedSections(sorted);
    setEnabledSections(new Set([...defaults, ...REPORT_SECTIONS.filter((s) => s.required).map((s) => s.id)]));
  }

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
    if (needsVulns && filteredVulns.length === 0) { toast.error("No vulnerabilities match the selected filters."); return; }
    if (enabledSections.size === 0) { toast.error("Select at least one report section."); return; }
    try {
      const result = await generateReport.mutateAsync({
        subproject: spId,
        format,
        risk_levels: selectedRiskLevels,
        statuses: selectedStatuses,
        report_type: reportType || undefined,
        sections: orderedSections.filter((id) => enabledSections.has(id)),
        audience: rptAudience,
        ...(rptStyle         ? { style: rptStyle }                 : {}),
        ...(rptExtra         ? { extra: rptExtra }                 : {}),
        ...(rptChartsEnabled ? { charts_enabled: rptChartsEnabled } : {}),
        ...(rptChartsVariants? { charts_variants: rptChartsVariants} : {}),
      });
      setGeneratedExportId(result.id);
      toast.success("Report generation started!");
    } catch {
      toast.error("Failed to start report generation.");
    }
  }

  const countByLevel = (level: string) => filteredVulns.filter((v) => v.risk_level === level).length;
  const categories = Array.from(new Set(REPORT_TYPES.map((r) => r.category)));

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

          {/* 1. Report type */}
          <div className="card">
            <h3 className="font-semibold text-slate-100 mb-4">Report Type</h3>
            {categories.map((cat) => (
              <div key={cat} className="mb-4 last:mb-0">
                <p className="text-xs text-slate-500 uppercase tracking-wider font-medium mb-2">{cat}</p>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {REPORT_TYPES.filter((r) => r.category === cat).map((rt) => (
                    <button
                      key={rt.id}
                      onClick={() => selectReportType(rt.id)}
                      className={`text-left rounded-lg border px-3 py-2.5 text-xs transition-colors ${
                        reportType === rt.id
                          ? "border-blue-500 bg-blue-950/60 text-blue-200"
                          : "border-slate-700 hover:border-slate-500 text-slate-300"
                      }`}
                    >
                      <p className="font-medium leading-tight">{rt.label}</p>
                      <p className="text-slate-500 mt-0.5 leading-tight text-[11px] line-clamp-2">{rt.desc}</p>
                      {!rt.hasVulns && (
                        <span className="inline-block mt-1 text-[10px] px-1 rounded bg-slate-800 text-slate-500">no vulns required</span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            ))}
            <div className="flex items-center gap-2 mt-3 text-xs text-slate-500">
              <Info className="h-3.5 w-3.5 shrink-0" />
              {reportType
                ? "Sections pre-selected for this report type — adjust below as needed."
                : "Optional: select a type to apply a section preset. All sections are enabled by default."}
            </div>
          </div>

          {/* 2. Report sections */}
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

          {/* 3. Output format */}
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

          {/* 4. Severity & status filters (only for vuln-based reports) */}
          {needsVulns && (
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
          )}

          {/* Export result */}
          {generatedExportId && <ExportStatusCard exportId={generatedExportId} />}
        </div>

        {/* ── Right column ── */}
        <div className="space-y-4">
          {/* Section preview */}
          <SectionPreview orderedIds={orderedSections} enabledIds={enabledSections} />

          {/* Vuln summary */}
          {needsVulns && (
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
                {filteredVulns.length === 0 && needsVulns && (
                  <p className="text-xs text-amber-400 mt-1">No vulnerabilities match the current filters.</p>
                )}
              </div>
            </div>
          )}

          {/* Generate card */}
          <div className="card sticky top-6">
            <h3 className="font-semibold text-slate-100 mb-4">Generate Report</h3>
            <div className="space-y-2 mb-4 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-500">Format</span>
                <span className="text-slate-200 font-medium uppercase">{format}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Type</span>
                <span className="text-slate-200 font-medium text-right text-xs max-w-[60%] truncate">
                  {selectedTypeInfo?.label ?? "—"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Sections</span>
                <span className="text-slate-200 font-medium">{enabledSections.size}</span>
              </div>
              {needsVulns && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Vulnerabilities</span>
                  <span className="text-slate-200 font-medium">{filteredVulns.length}</span>
                </div>
              )}
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
            {canExport && needsVulns && filteredVulns.length === 0 && (
              <p className="text-xs text-amber-400 mt-2 text-center">No vulnerabilities match the filters.</p>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}

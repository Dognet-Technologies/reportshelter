/**
 * Report builder: format selection, vulnerability filters, generation trigger,
 * polling for status, and download link when done.
 */
import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  Loader2,
  FileText,
  Download,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Clock,
  ChevronRight,
} from "lucide-react";
import toast from "react-hot-toast";
import {
  useVulnerabilities,
  useGenerateReport,
  useReportExport,
  useLicenseStatus,
} from "@/api/hooks";
import { Layout } from "@/components/Layout";
import { SeverityBadge } from "@/components/SeverityBadge";
import type { RiskLevel, VulnStatus, ReportFormat } from "@/api/types";

const RISK_LEVELS: RiskLevel[] = ["Critical", "High", "Medium", "Low", "Info"];
const STATUSES: VulnStatus[] = ["Open", "Fixed", "Accepted", "Retest"];
const FORMATS: { value: ReportFormat; label: string; desc: string }[] = [
  { value: "pdf", label: "PDF", desc: "Professional printable document via WeasyPrint" },
  { value: "html", label: "HTML", desc: "Standalone HTML with embedded assets" },
  { value: "xml", label: "XML", desc: "Structured data for interoperability" },
];

// ─── Export Status Watcher ────────────────────────────────────────────────────

function ExportStatusCard({ exportId }: { exportId: number }) {
  const { data: exp } = useReportExport(exportId);
  const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

  if (!exp) return null;

  return (
    <div className={`card border ${
      exp.status === "done"
        ? "border-green-700"
        : exp.status === "failed"
        ? "border-red-700"
        : "border-slate-700"
    }`}>
      <div className="flex items-center gap-3">
        {exp.status === "pending" && <Clock className="h-5 w-5 text-amber-400" />}
        {exp.status === "generating" && <RefreshCw className="h-5 w-5 text-blue-400 animate-spin" />}
        {exp.status === "done" && <CheckCircle2 className="h-5 w-5 text-green-400" />}
        {exp.status === "failed" && <AlertCircle className="h-5 w-5 text-red-400" />}

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
            <p className="text-sm text-slate-500 mt-1">
              This may take a minute. The page will update automatically.
            </p>
          )}
        </div>

        {exp.status === "done" && (
          <a
            href={`${BASE_URL}/reports/exports/${exportId}/download/`}
            download
            className="btn-primary shrink-0"
          >
            <Download className="h-4 w-4" />
            Download {exp.format.toUpperCase()}
          </a>
        )}
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ReportBuilderPage() {
  const { subprojectId } = useParams<{ subprojectId: string }>();
  const spId = Number(subprojectId);

  const { data: vulns } = useVulnerabilities(spId);
  const { data: license } = useLicenseStatus();
  const generateReport = useGenerateReport();

  const [format, setFormat] = useState<ReportFormat>("pdf");
  const [selectedRiskLevels, setSelectedRiskLevels] = useState<RiskLevel[]>([...RISK_LEVELS]);
  const [selectedStatuses, setSelectedStatuses] = useState<VulnStatus[]>(["Open", "Retest"]);
  const [generatedExportId, setGeneratedExportId] = useState<number | null>(null);

  const canExport = license?.is_active ?? false;

  // Filter preview
  const filteredVulns = (vulns ?? []).filter(
    (v) =>
      selectedRiskLevels.includes(v.risk_level) &&
      selectedStatuses.includes(v.vuln_status)
  );

  function toggleRiskLevel(level: RiskLevel) {
    setSelectedRiskLevels((prev) =>
      prev.includes(level) ? prev.filter((l) => l !== level) : [...prev, level]
    );
  }

  function toggleStatus(status: VulnStatus) {
    setSelectedStatuses((prev) =>
      prev.includes(status) ? prev.filter((s) => s !== status) : [...prev, status]
    );
  }

  async function handleGenerate() {
    if (!canExport) {
      toast.error("Report export is disabled on your current plan.");
      return;
    }
    if (filteredVulns.length === 0) {
      toast.error("No vulnerabilities match the selected filters.");
      return;
    }
    try {
      const result = await generateReport.mutateAsync({
        subproject: spId,
        format,
        risk_levels: selectedRiskLevels,
        statuses: selectedStatuses,
      });
      setGeneratedExportId(result.id);
      toast.success("Report generation started!");
    } catch {
      toast.error("Failed to start report generation.");
    }
  }

  // Summary counts for filter preview
  const countByLevel = (level: RiskLevel) =>
    filteredVulns.filter((v) => v.risk_level === level).length;

  return (
    <Layout>
      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 text-sm text-slate-500 mb-4 flex-wrap">
        <Link to="/projects" className="hover:text-slate-300">Projects</Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <Link to="/projects" className="hover:text-slate-300">
          Projects
        </Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="text-slate-300">Report Builder</span>
      </div>

      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Report Builder</h1>
          <p className="text-slate-400 text-sm mt-1">Sub-project #{spId}</p>
        </div>
        <FileText className="h-8 w-8 text-slate-600" />
      </div>

      {!canExport && (
        <div className="rounded-md border border-amber-700 bg-amber-950/50 px-4 py-3 text-sm text-amber-300 mb-6">
          Report export is not available on your current plan.{" "}
          <Link to="/settings" className="underline font-medium">
            Upgrade to PRO
          </Link>{" "}
          to generate and download reports.
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Config */}
        <div className="lg:col-span-2 space-y-6">
          {/* Format selection */}
          <div className="card">
            <h3 className="font-semibold text-slate-100 mb-4">Output Format</h3>
            <div className="grid grid-cols-3 gap-3">
              {FORMATS.map((f) => (
                <button
                  key={f.value}
                  onClick={() => setFormat(f.value)}
                  className={`rounded-lg border p-4 text-left transition-colors ${
                    format === f.value
                      ? "border-blue-500 bg-blue-950/40"
                      : "border-slate-700 hover:border-slate-500"
                  }`}
                >
                  <p className="font-semibold text-slate-100 text-sm">{f.label}</p>
                  <p className="text-xs text-slate-500 mt-1">{f.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Severity filters */}
          <div className="card">
            <h3 className="font-semibold text-slate-100 mb-4">Include Severities</h3>
            <div className="flex flex-wrap gap-2">
              {RISK_LEVELS.map((level) => {
                const selected = selectedRiskLevels.includes(level);
                return (
                  <button
                    key={level}
                    onClick={() => toggleRiskLevel(level)}
                    className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm transition-colors ${
                      selected
                        ? "border-transparent"
                        : "border-slate-700 bg-transparent opacity-40"
                    }`}
                  >
                    <SeverityBadge level={level} />
                    <span className={`text-xs font-medium ${selected ? "text-slate-200" : "text-slate-500"}`}>
                      ({countByLevel(level)})
                    </span>
                    {selected ? "✓" : ""}
                  </button>
                );
              })}
            </div>
            <div className="flex gap-2 mt-3">
              <button
                onClick={() => setSelectedRiskLevels([...RISK_LEVELS])}
                className="text-xs text-blue-400 hover:text-blue-300"
              >
                Select all
              </button>
              <span className="text-slate-600">·</span>
              <button
                onClick={() => setSelectedRiskLevels([])}
                className="text-xs text-slate-400 hover:text-slate-200"
              >
                Clear all
              </button>
            </div>
          </div>

          {/* Status filters */}
          <div className="card">
            <h3 className="font-semibold text-slate-100 mb-4">Include Statuses</h3>
            <div className="flex flex-wrap gap-2">
              {STATUSES.map((status) => {
                const selected = selectedStatuses.includes(status);
                const count = (vulns ?? []).filter(
                  (v) => v.vuln_status === status && selectedRiskLevels.includes(v.risk_level)
                ).length;
                return (
                  <button
                    key={status}
                    onClick={() => toggleStatus(status)}
                    className={`rounded-full border px-3 py-1.5 text-sm font-medium transition-colors ${
                      selected
                        ? "bg-slate-700 border-slate-500 text-slate-100"
                        : "border-slate-700 text-slate-500 hover:border-slate-500"
                    }`}
                  >
                    {status} ({count})
                  </button>
                );
              })}
            </div>
          </div>

          {/* Export status */}
          {generatedExportId && (
            <ExportStatusCard exportId={generatedExportId} />
          )}
        </div>

        {/* Right: Preview & Generate */}
        <div className="space-y-4">
          <div className="card sticky top-6">
            <h3 className="font-semibold text-slate-100 mb-4">Report Summary</h3>
            <div className="space-y-2 mb-4">
              <div className="flex justify-between text-sm">
                <span className="text-slate-500">Format</span>
                <span className="text-slate-200 font-medium uppercase">{format}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-500">Vulnerabilities</span>
                <span className="text-slate-200 font-medium">{filteredVulns.length}</span>
              </div>
              {RISK_LEVELS.map((level) => {
                const c = countByLevel(level);
                if (c === 0) return null;
                return (
                  <div key={level} className="flex justify-between text-xs">
                    <span className="text-slate-500 pl-3">{level}</span>
                    <SeverityBadge level={level} />
                  </div>
                );
              })}
            </div>

            <div className="border-t border-slate-800 pt-4">
              <button
                onClick={handleGenerate}
                disabled={!canExport || generateReport.isPending || filteredVulns.length === 0}
                className="btn-primary w-full"
              >
                {generateReport.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Starting…
                  </>
                ) : (
                  <>
                    <FileText className="h-4 w-4" />
                    Generate {format.toUpperCase()}
                  </>
                )}
              </button>
              {filteredVulns.length === 0 && (
                <p className="text-xs text-amber-400 mt-2 text-center">
                  No vulnerabilities match the current filters.
                </p>
              )}
            </div>
          </div>

          {/* Vulnerability preview list */}
          {filteredVulns.length > 0 && (
            <div className="card">
              <h3 className="font-semibold text-slate-100 mb-3 text-sm">
                Included ({filteredVulns.length})
              </h3>
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {filteredVulns.map((v) => (
                  <div key={v.id} className="flex items-center gap-2">
                    <SeverityBadge level={v.risk_level} />
                    <span className="text-xs text-slate-300 truncate">{v.title}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}

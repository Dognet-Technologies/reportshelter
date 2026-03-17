/**
 * Sub-project detail page: vulnerability table with filters, scan import
 * (drag & drop), report exports, and screenshots.
 */
import { useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import { useDropzone } from "react-dropzone";
import {
  Upload,
  Loader2,
  FileText,
  Download,
  Image,
  AlertCircle,
  CheckCircle2,
  Clock,
  RefreshCw,
  Plus,
  ChevronRight,
} from "lucide-react";
import { format } from "date-fns";
import toast from "react-hot-toast";
import {
  useSubProject,
  useVulnerabilities,
  useUploadScan,
  useScanImport,
  useReportExports,
  useScreenshots,
  useUploadScreenshot,
} from "@/api/hooks";
import { Layout } from "@/components/Layout";
import { VulnerabilityTable } from "@/components/VulnerabilityTable";
import { useLicenseStatus } from "@/api/hooks";
import type { RiskLevel, VulnStatus, ScanImport } from "@/api/types";

// ─── Scan Import Section ──────────────────────────────────────────────────────

const SCANNER_OPTIONS = [
  { value: "nmap", label: "Nmap (XML)" },
  { value: "nikto", label: "Nikto (XML)" },
  { value: "burp", label: "Burp Suite (XML)" },
  { value: "zap", label: "OWASP ZAP (XML/JSON)" },
  { value: "metasploit", label: "Metasploit (XML)" },
  { value: "csv", label: "Generic CSV" },
];

function ImportStatusBadge({ status }: { status: ScanImport["status"] }) {
  const config = {
    pending: { icon: <Clock className="h-3.5 w-3.5" />, text: "Pending", cls: "text-amber-400" },
    processing: {
      icon: <RefreshCw className="h-3.5 w-3.5 animate-spin" />,
      text: "Processing",
      cls: "text-blue-400",
    },
    done: { icon: <CheckCircle2 className="h-3.5 w-3.5" />, text: "Done", cls: "text-green-400" },
    failed: { icon: <AlertCircle className="h-3.5 w-3.5" />, text: "Failed", cls: "text-red-400" },
  };
  const c = config[status];
  return (
    <span className={`inline-flex items-center gap-1 text-xs ${c.cls}`}>
      {c.icon} {c.text}
    </span>
  );
}

function ImportWatcher({ importId }: { importId: number }) {
  const { data } = useScanImport(importId);
  if (!data) return null;
  return (
    <div className="flex items-center justify-between text-xs py-2 border-b border-slate-800 last:border-0">
      <div>
        <span className="text-slate-300 font-medium">{data.original_filename}</span>
        <span className="ml-2 text-slate-500">{data.tool.toUpperCase()}</span>
      </div>
      <div className="flex items-center gap-3">
        {data.status === "done" && (
          <span className="text-slate-400">{data.vulnerability_count} found</span>
        )}
        {data.error_message && (
          <span className="text-red-400 truncate max-w-xs">{data.error_message}</span>
        )}
        <ImportStatusBadge status={data.status} />
      </div>
    </div>
  );
}

interface ScanImportSectionProps {
  subprojectId: number;
  canImport: boolean;
}

function ScanImportSection({ subprojectId, canImport }: ScanImportSectionProps) {
  const [scannerType, setScannerType] = useState("nmap");
  const [recentImports, setRecentImports] = useState<number[]>([]);
  const upload = useUploadScan(subprojectId);

  const onDrop = useCallback(
    async (files: File[]) => {
      if (!canImport) {
        toast.error("Your license does not allow scan imports.");
        return;
      }
      const file = files[0];
      if (!file) return;
      const formData = new FormData();
      formData.append("file", file);
      formData.append("tool", scannerType);
      try {
        const result = await upload.mutateAsync(formData);
        setRecentImports((prev) => [result.id, ...prev]);
        toast.success(`Import started for ${file.name}`);
      } catch {
        toast.error("Failed to start import.");
      }
    },
    [canImport, scannerType, upload]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxFiles: 1,
    disabled: !canImport || upload.isPending,
  });

  return (
    <div className="card">
      <h3 className="font-semibold text-slate-100 mb-4 flex items-center gap-2">
        <Upload className="h-4 w-4" />
        Import Scan
      </h3>

      {!canImport && (
        <div className="rounded-md border border-amber-700 bg-amber-950/50 px-4 py-3 text-sm text-amber-300 mb-4">
          Scan import is disabled on your current plan.{" "}
          <Link to="/settings" className="underline">
            Upgrade to PRO
          </Link>
        </div>
      )}

      <div className="mb-3">
        <label className="label">Scanner type</label>
        <select
          value={scannerType}
          onChange={(e) => setScannerType(e.target.value)}
          className="input w-full sm:w-64"
          disabled={!canImport}
        >
          {SCANNER_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>

      <div
        {...getRootProps()}
        className={`rounded-lg border-2 border-dashed p-8 text-center cursor-pointer transition-colors ${
          isDragActive
            ? "border-blue-500 bg-blue-950/30"
            : canImport
            ? "border-slate-700 hover:border-slate-500"
            : "border-slate-800 opacity-50 cursor-not-allowed"
        }`}
      >
        <input {...getInputProps()} />
        {upload.isPending ? (
          <div className="flex flex-col items-center gap-2 text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin" />
            <span className="text-sm">Uploading…</span>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2 text-slate-500">
            <Upload className="h-8 w-8" />
            <p className="text-sm font-medium">
              {isDragActive ? "Drop your file here" : "Drag & drop or click to upload"}
            </p>
            <p className="text-xs">XML, JSON, or CSV · max 50MB</p>
          </div>
        )}
      </div>

      {recentImports.length > 0 && (
        <div className="mt-4">
          <p className="text-xs text-slate-500 mb-2">Recent imports:</p>
          {recentImports.map((id) => (
            <ImportWatcher key={id} importId={id} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Screenshots Section ──────────────────────────────────────────────────────

interface ScreenshotsSectionProps {
  projectId: number;
  subprojectId: number;
}

function ScreenshotsSection({ projectId, subprojectId }: ScreenshotsSectionProps) {
  const { data: screenshots } = useScreenshots(projectId, subprojectId);
  const upload = useUploadScreenshot(projectId, subprojectId);

  const onDrop = useCallback(
    async (files: File[]) => {
      const file = files[0];
      if (!file) return;
      const formData = new FormData();
      formData.append("image", file);
      formData.append("caption", file.name);
      try {
        await upload.mutateAsync(formData);
        toast.success("Screenshot uploaded.");
      } catch {
        toast.error("Failed to upload screenshot.");
      }
    },
    [upload]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { "image/*": [] },
    maxFiles: 1,
    disabled: upload.isPending,
  });

  return (
    <div className="card">
      <h3 className="font-semibold text-slate-100 mb-4 flex items-center gap-2">
        <Image className="h-4 w-4" />
        Screenshots ({screenshots?.length ?? 0})
      </h3>

      <div
        {...getRootProps()}
        className={`rounded-lg border-2 border-dashed p-4 text-center cursor-pointer transition-colors mb-4 ${
          isDragActive ? "border-blue-500 bg-blue-950/30" : "border-slate-700 hover:border-slate-500"
        }`}
      >
        <input {...getInputProps()} />
        {upload.isPending ? (
          <Loader2 className="h-5 w-5 animate-spin mx-auto text-slate-400" />
        ) : (
          <p className="text-sm text-slate-500">
            <Plus className="h-4 w-4 inline mr-1" />
            Add screenshot
          </p>
        )}
      </div>

      {screenshots && screenshots.length > 0 ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          {screenshots.map((s) => (
            <a
              key={s.id}
              href={s.image}
              target="_blank"
              rel="noopener noreferrer"
              className="group relative rounded-lg overflow-hidden border border-slate-800 hover:border-blue-600 transition-colors"
            >
              <img
                src={s.image}
                alt={s.caption}
                className="w-full h-24 object-cover"
              />
              {s.caption && (
                <p className="px-2 py-1 text-xs text-slate-400 truncate border-t border-slate-800">
                  {s.caption}
                </p>
              )}
            </a>
          ))}
        </div>
      ) : (
        <p className="text-slate-500 text-sm text-center py-4">No screenshots yet.</p>
      )}
    </div>
  );
}

// ─── Report Exports Section ───────────────────────────────────────────────────

interface ReportExportsSectionProps {
  subprojectId: number;
  projectId: number;
}

function ReportExportsSection({ subprojectId, projectId }: ReportExportsSectionProps) {
  const { data: exports } = useReportExports(subprojectId);

  const statusIcon = {
    pending: <Clock className="h-4 w-4 text-amber-400" />,
    generating: <RefreshCw className="h-4 w-4 text-blue-400 animate-spin" />,
    done: <CheckCircle2 className="h-4 w-4 text-green-400" />,
    failed: <AlertCircle className="h-4 w-4 text-red-400" />,
  };

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-semibold text-slate-100 flex items-center gap-2">
          <FileText className="h-4 w-4" />
          Report Exports
        </h3>
        <Link
          to={`/reports/builder/${subprojectId}`}
          className="btn-primary text-xs py-1.5"
        >
          <Plus className="h-3.5 w-3.5" />
          Generate Report
        </Link>
      </div>

      {!exports || exports.length === 0 ? (
        <p className="text-slate-500 text-sm text-center py-4">No reports generated yet.</p>
      ) : (
        <div className="space-y-2">
          {exports.map((exp) => (
            <div
              key={exp.id}
              className="flex items-center justify-between py-2 border-b border-slate-800 last:border-0"
            >
              <div className="flex items-center gap-3">
                {statusIcon[exp.status]}
                <div>
                  <p className="text-sm font-medium text-slate-200 uppercase">{exp.format}</p>
                  <p className="text-xs text-slate-500">
                    {format(new Date(exp.created_at), "MMM d, yyyy HH:mm")}
                  </p>
                </div>
              </div>
              {exp.status === "done" && exp.file_url && (
                <a
                  href={`${import.meta.env.VITE_API_BASE_URL ?? "/api/v1"}/reports/exports/${exp.id}/download/`}
                  className="btn-secondary text-xs py-1.5"
                  download
                >
                  <Download className="h-3.5 w-3.5" />
                  Download
                </a>
              )}
              {exp.status === "failed" && (
                <span className="text-xs text-red-400 truncate max-w-xs">
                  {exp.error_message}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SubProjectPage() {
  const { projectId, id } = useParams<{ projectId: string; id: string }>();
  const pId = Number(projectId);
  const spId = Number(id);

  const { data: subproject, isLoading } = useSubProject(pId, spId);
  const { data: license } = useLicenseStatus();

  const [riskFilter, setRiskFilter] = useState<RiskLevel | "">("");
  const [statusFilter, setStatusFilter] = useState<VulnStatus | "">("");

  const { data: vulnerabilities, isLoading: vulnLoading } = useVulnerabilities(
    spId,
    {
      ...(riskFilter ? { risk_level: riskFilter } : {}),
      ...(statusFilter ? { vuln_status: statusFilter } : {}),
    }
  );

  const RISK_LEVELS: RiskLevel[] = ["Critical", "High", "Medium", "Low", "Info"];
  const STATUSES: VulnStatus[] = ["Open", "Fixed", "Accepted", "Retest"];

  if (isLoading) {
    return (
      <Layout>
        <div className="flex items-center justify-center py-20 text-slate-500">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          Loading…
        </div>
      </Layout>
    );
  }

  if (!subproject) {
    return (
      <Layout>
        <p className="text-slate-400 text-center py-20">Sub-project not found.</p>
      </Layout>
    );
  }

  return (
    <Layout>
      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 text-sm text-slate-500 mb-4 flex-wrap">
        <Link to="/projects" className="hover:text-slate-300">Projects</Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <Link to={`/projects/${pId}`} className="hover:text-slate-300">
          Project
        </Link>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="text-slate-300">{subproject.title}</span>
      </div>

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">{subproject.title}</h1>
          <p className="text-slate-400 text-sm mt-1">
            {format(new Date(subproject.scan_date), "MMMM d, yyyy")}
          </p>
          {subproject.description && (
            <p className="text-slate-500 text-sm mt-1">{subproject.description}</p>
          )}
        </div>
        <Link
          to={`/reports/builder/${spId}`}
          className="btn-primary shrink-0"
        >
          <FileText className="h-4 w-4" />
          Generate Report
        </Link>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-3 mb-6">
        {[
          { label: "Critical", count: subproject.critical_count, color: "text-red-400" },
          { label: "High", count: subproject.high_count, color: "text-orange-400" },
          { label: "Medium", count: subproject.medium_count, color: "text-yellow-400" },
          { label: "Low", count: subproject.low_count, color: "text-blue-400" },
          { label: "Info", count: subproject.info_count, color: "text-slate-400" },
          { label: "Open", count: subproject.open_count, color: "text-red-300" },
        ].map((s) => (
          <div key={s.label} className="card py-3 px-4 text-center">
            <p className={`text-xl font-bold ${s.color}`}>{s.count}</p>
            <p className="text-xs text-slate-500 mt-0.5">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Vulnerabilities */}
        <div className="lg:col-span-2 space-y-4">
          <div className="card">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
              <h3 className="font-semibold text-slate-100">
                Vulnerabilities ({vulnerabilities?.length ?? 0})
              </h3>
              <div className="flex items-center gap-2 flex-wrap">
                <select
                  value={riskFilter}
                  onChange={(e) => setRiskFilter(e.target.value as RiskLevel | "")}
                  className="input py-1 text-xs w-36"
                >
                  <option value="">All Severities</option>
                  {RISK_LEVELS.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value as VulnStatus | "")}
                  className="input py-1 text-xs w-32"
                >
                  <option value="">All Statuses</option>
                  {STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <VulnerabilityTable
              vulnerabilities={vulnerabilities ?? []}
              loading={vulnLoading}
            />
          </div>
        </div>

        {/* Right: Sidebar panels */}
        <div className="space-y-4">
          <ScanImportSection
            subprojectId={spId}
            canImport={license?.is_active ?? false}
          />
          <ReportExportsSection subprojectId={spId} projectId={pId} />
          <ScreenshotsSection projectId={pId} subprojectId={spId} />
        </div>
      </div>
    </Layout>
  );
}

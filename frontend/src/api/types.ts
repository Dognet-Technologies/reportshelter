/**
 * Shared TypeScript types for all API entities.
 * Field names match exactly what the Django REST API returns.
 */

// ─── Auth ────────────────────────────────────────────────────────────────────

export interface User {
  id: number;
  email: string;
  first_name: string;
  last_name: string;
  full_name: string;
  role: "admin" | "member";
  organization_id: number;
  is_email_verified: boolean;
  date_joined: string;
  last_login: string | null;
}

export interface Organization {
  id: number;
  name: string;
  slug: string;
  address: string;
  phone: string;
  email: string;
  website: string;
  vat_number: string;
  legal_disclaimer: string;
  logo: string | null;
  primary_color: string;
  secondary_color: string;
  created_at: string;
  updated_at: string;
}

// ─── License ─────────────────────────────────────────────────────────────────

export type LicenseStatusCode =
  | "trial_active"
  | "trial_expired"
  | "pro_active"
  | "pro_expired"
  | "invalid";

export interface LicenseStatus {
  status: LicenseStatusCode;
  license_key: string | null;
  trial_started_at: string | null;
  trial_expires_at: string | null;
  pro_activated_at: string | null;
  pro_expires_at: string | null;
  last_checked_at: string | null;
  days_remaining: number | null;
  is_active: boolean;
  is_trial: boolean;
  is_expired: boolean;
}

// ─── Projects ────────────────────────────────────────────────────────────────

export interface ProjectLock {
  locked_by: number | null;
  locked_by_name: string;
  locked_at: string;
  last_heartbeat: string;
  is_expired: boolean;
}

export interface Project {
  id: number;
  organization: number;
  title: string;
  description: string;
  start_date: string | null;
  // Client
  client_name: string;
  client_logo: string | null;
  client_contact: string;
  client_email: string;
  client_phone: string;
  // Graphic
  primary_color: string;
  secondary_color: string;
  font_family: string;
  watermark_text: string;
  watermark_image: string | null;
  watermark_opacity: number;
  // Header / Footer
  header_logo_left: boolean;
  header_text_center: string;
  header_show_date: boolean;
  footer_text: string;
  footer_page_numbering: "n_of_total" | "n_only" | "none";
  // Template
  template_name: string;
  template_html: string | null;
  // Relations
  subproject_count: number;
  lock: ProjectLock | null;
  created_by: User | null;
  created_at: string;
  updated_at: string;
}

export interface SubProject {
  id: number;
  project: number;
  title: string;
  description: string;
  scan_date: string | null;
  vulnerability_count: number;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

// ─── Vulnerabilities ─────────────────────────────────────────────────────────

export type RiskLevel = "critical" | "high" | "medium" | "low" | "info";
export type VulnStatus = "open" | "fixed" | "accepted" | "retest";

export interface Vulnerability {
  id: number;
  subproject: number;
  scan_import: number | null;
  title: string;
  description: string;
  remediation: string;
  affected_host: string;
  affected_port: string;
  affected_service: string;
  cve_id: string;
  cvss_score: number | null;
  cvss_vector: string;
  epss_score: number | null;
  risk_level: RiskLevel;
  risk_score: number | null;
  vuln_status: VulnStatus;
  sources: string[];
  is_recurring: boolean;
  evidence_code: string;
  created_at: string;
  updated_at: string;
}

export interface DiffResult {
  new: Vulnerability[];
  fixed: Vulnerability[];
  persistent: Vulnerability[];
  changed: Vulnerability[];
}

export interface TimelinePoint {
  subproject_id: number;
  subproject_title: string;
  scan_date: string | null;
  total: number;
  by_severity: Record<RiskLevel, number>;
  average_risk_score: number;
  new: number;
  fixed: number;
  persistent: number;
}

// ─── Scan Imports ────────────────────────────────────────────────────────────

export type ScanTool = "nmap" | "nikto" | "burp" | "zap" | "metasploit" | "csv" | "unknown";
export type ImportStatus = "pending" | "processing" | "done" | "failed";

export interface ScanImport {
  id: number;
  subproject: number;
  tool: ScanTool;
  original_filename: string;
  status: ImportStatus;
  error_message: string;
  vulnerability_count: number;
  imported_by: number | null;
  imported_at: string;
  processed_at: string | null;
}

// ─── Screenshots ─────────────────────────────────────────────────────────────

export interface Screenshot {
  id: number;
  subproject: number;
  vulnerability_ref: number | null;
  image: string;
  caption: string;
  order: number;
  uploaded_by: number | null;
  uploaded_at: string;
}

// ─── Reports ─────────────────────────────────────────────────────────────────

export type ReportFormat = "pdf" | "html" | "xml";
export type ExportStatus = "pending" | "generating" | "done" | "failed";

export interface ReportExport {
  id: number;
  subproject: number;
  format: ReportFormat;
  status: ExportStatus;
  file_url: string | null;
  error_message: string;
  options: {
    risk_levels?: RiskLevel[];
    vuln_status?: VulnStatus[];
  };
  generated_by: number | null;
  created_at: string;
  completed_at: string | null;
}

// ─── Pagination ──────────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

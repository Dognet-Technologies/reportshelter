/**
 * React Query hooks for all CyberReport Pro API endpoints.
 */
import {
  useQuery,
  useMutation,
  useQueryClient,
  type UseQueryOptions,
} from "@tanstack/react-query";
import { apiClient } from "./client";
import type {
  User,
  Organization,
  LicenseStatus,
  Project,
  SubProject,
  Vulnerability,
  DiffResult,
  TimelinePoint,
  ScanImport,
  ReportExport,
  ReportFormat,
  Screenshot,
  PaginatedResponse,
  RiskLevel,
  VulnStatus,
} from "./types";

// ─── Query Keys ──────────────────────────────────────────────────────────────

export const queryKeys = {
  me: ["auth", "me"] as const,
  organization: ["auth", "organization"] as const,
  users: ["auth", "users"] as const,
  licenseStatus: ["licensing", "status"] as const,
  projects: (params?: Record<string, unknown>) => ["projects", params] as const,
  project: (id: number) => ["projects", id] as const,
  subprojects: (projectId: number) => ["projects", projectId, "subprojects"] as const,
  subproject: (projectId: number, spId: number) =>
    ["projects", projectId, "subprojects", spId] as const,
  vulnerabilities: (subprojectId: number) => ["vulnerabilities", subprojectId] as const,
  vulnerability: (id: number) => ["vulnerabilities", "detail", id] as const,
  diff: (currentId: number, previousId: number) =>
    ["vulnerabilities", "diff", currentId, previousId] as const,
  timeline: (projectId: number) => ["vulnerabilities", "timeline", projectId] as const,
  scanImport: (importId: number) => ["vulnerabilities", "imports", importId] as const,
  reportExports: (subprojectId: number) => ["reports", "exports", subprojectId] as const,
  reportExport: (exportId: number) => ["reports", "exports", "detail", exportId] as const,
  screenshots: (subprojectId: number) => ["screenshots", subprojectId] as const,
};

// ─── Auth hooks ──────────────────────────────────────────────────────────────

export function useMe(options?: Partial<UseQueryOptions<User>>) {
  return useQuery<User>({
    queryKey: queryKeys.me,
    queryFn: () => apiClient.get<User>("/auth/me/").then((r) => r.data),
    ...options,
  });
}

export function useOrganization(options?: Partial<UseQueryOptions<Organization>>) {
  return useQuery<Organization>({
    queryKey: queryKeys.organization,
    queryFn: () => apiClient.get<Organization>("/auth/organization/").then((r) => r.data),
    ...options,
  });
}

export function useUsers(options?: Partial<UseQueryOptions<User[]>>) {
  return useQuery<User[]>({
    queryKey: queryKeys.users,
    queryFn: () =>
      apiClient
        .get<PaginatedResponse<User>>("/auth/users/")
        .then((r) => r.data.results),
    ...options,
  });
}

export function useUpdateMe() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<User>) =>
      apiClient.patch<User>("/auth/me/", data).then((r) => r.data),
    onSuccess: (user) => {
      qc.setQueryData(queryKeys.me, user);
    },
  });
}

export function useInviteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { email: string; role: "admin" | "member"; first_name?: string; last_name?: string }) =>
      apiClient.post("/auth/users/invite/", data).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.users });
    },
  });
}

// ─── License hooks ───────────────────────────────────────────────────────────

export function useLicenseStatus(options?: Partial<UseQueryOptions<LicenseStatus>>) {
  return useQuery<LicenseStatus>({
    queryKey: queryKeys.licenseStatus,
    queryFn: () => apiClient.get<LicenseStatus>("/licensing/status/").then((r) => r.data),
    staleTime: 1000 * 60, // 1 minute
    ...options,
  });
}

export function useActivateLicense() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { license_key: string }) =>
      apiClient.post<LicenseStatus>("/licensing/activate/", data).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.licenseStatus });
    },
  });
}

// ─── Project hooks ───────────────────────────────────────────────────────────

export function useProjects(params?: { search?: string; page?: number }) {
  return useQuery<PaginatedResponse<Project>>({
    queryKey: queryKeys.projects(params),
    queryFn: () =>
      apiClient
        .get<PaginatedResponse<Project>>("/projects/", { params })
        .then((r) => r.data),
  });
}

export function useProject(id: number, options?: Partial<UseQueryOptions<Project>>) {
  return useQuery<Project>({
    queryKey: queryKeys.project(id),
    queryFn: () => apiClient.get<Project>(`/projects/${id}/`).then((r) => r.data),
    enabled: id > 0,
    ...options,
  });
}

export function useCreateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<Project>) =>
      apiClient.post<Project>("/projects/", data).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects"] });
    },
  });
}

export function useUpdateProject(id: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<Project>) =>
      apiClient.patch<Project>(`/projects/${id}/`, data).then((r) => r.data),
    onSuccess: (project) => {
      qc.setQueryData(queryKeys.project(id), project);
      qc.invalidateQueries({ queryKey: ["projects"] });
    },
  });
}

export function useDeleteProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiClient.delete(`/projects/${id}/`).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects"] });
    },
  });
}

// ─── Lock hooks ───────────────────────────────────────────────────────────────

export function useAcquireLock(projectId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiClient.post(`/projects/${projectId}/lock/acquire/`).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.project(projectId) });
    },
  });
}

export function useHeartbeat(projectId: number) {
  return useMutation({
    mutationFn: () =>
      apiClient.post(`/projects/${projectId}/lock/heartbeat/`).then((r) => r.data),
  });
}

export function useReleaseLock(projectId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiClient.post(`/projects/${projectId}/lock/release/`).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.project(projectId) });
    },
  });
}

// ─── SubProject hooks ────────────────────────────────────────────────────────

export function useSubProjects(
  projectId: number,
  options?: Partial<UseQueryOptions<SubProject[]>>
) {
  return useQuery<SubProject[]>({
    queryKey: queryKeys.subprojects(projectId),
    queryFn: () =>
      apiClient
        .get<PaginatedResponse<SubProject>>(`/projects/${projectId}/subprojects/`)
        .then((r) => r.data.results),
    enabled: projectId > 0,
    ...options,
  });
}

export function useSubProject(
  projectId: number,
  spId: number,
  options?: Partial<UseQueryOptions<SubProject>>
) {
  return useQuery<SubProject>({
    queryKey: queryKeys.subproject(projectId, spId),
    queryFn: () =>
      apiClient
        .get<SubProject>(`/projects/${projectId}/subprojects/${spId}/`)
        .then((r) => r.data),
    enabled: projectId > 0 && spId > 0,
    ...options,
  });
}

export function useCreateSubProject(projectId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<SubProject>) =>
      apiClient
        .post<SubProject>(`/projects/${projectId}/subprojects/`, data)
        .then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.subprojects(projectId) });
    },
  });
}

export function useUpdateSubProject(projectId: number, spId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<SubProject>) =>
      apiClient
        .patch<SubProject>(`/projects/${projectId}/subprojects/${spId}/`, data)
        .then((r) => r.data),
    onSuccess: (sp) => {
      qc.setQueryData(queryKeys.subproject(projectId, spId), sp);
      qc.invalidateQueries({ queryKey: queryKeys.subprojects(projectId) });
    },
  });
}

export function useDeleteSubProject(projectId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (spId: number) =>
      apiClient
        .delete(`/projects/${projectId}/subprojects/${spId}/`)
        .then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.subprojects(projectId) });
    },
  });
}

// ─── Vulnerability hooks ─────────────────────────────────────────────────────

export function useVulnerabilities(
  subprojectId: number,
  filters?: { risk_level?: RiskLevel; vuln_status?: VulnStatus },
  options?: Partial<UseQueryOptions<Vulnerability[]>>
) {
  return useQuery<Vulnerability[]>({
    queryKey: [...queryKeys.vulnerabilities(subprojectId), filters],
    queryFn: () =>
      apiClient
        .get<PaginatedResponse<Vulnerability>>("/vulnerabilities/", {
          params: { subproject: subprojectId, ...filters },
        })
        .then((r) => r.data.results),
    enabled: subprojectId > 0,
    ...options,
  });
}

export function useVulnerability(
  id: number,
  options?: Partial<UseQueryOptions<Vulnerability>>
) {
  return useQuery<Vulnerability>({
    queryKey: queryKeys.vulnerability(id),
    queryFn: () =>
      apiClient.get<Vulnerability>(`/vulnerabilities/${id}/`).then((r) => r.data),
    enabled: id > 0,
    ...options,
  });
}

export function useUpdateVulnerability(id: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<Vulnerability>) =>
      apiClient.patch<Vulnerability>(`/vulnerabilities/${id}/`, data).then((r) => r.data),
    onSuccess: (vuln) => {
      qc.setQueryData(queryKeys.vulnerability(id), vuln);
      qc.invalidateQueries({ queryKey: queryKeys.vulnerabilities(vuln.subproject) });
    },
  });
}

export function useDeleteVulnerability() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiClient.delete(`/vulnerabilities/${id}/`).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vulnerabilities"] });
    },
  });
}

// ─── Diff & Timeline hooks ───────────────────────────────────────────────────

export function useDiff(
  currentId: number,
  previousId: number,
  options?: Partial<UseQueryOptions<DiffResult>>
) {
  return useQuery<DiffResult>({
    queryKey: queryKeys.diff(currentId, previousId),
    queryFn: () =>
      apiClient
        .get<DiffResult>("/vulnerabilities/diff/", {
          params: { current: currentId, previous: previousId },
        })
        .then((r) => r.data),
    enabled: currentId > 0 && previousId > 0,
    ...options,
  });
}

export function useTimeline(
  projectId: number,
  options?: Partial<UseQueryOptions<TimelinePoint[]>>
) {
  return useQuery<TimelinePoint[]>({
    queryKey: queryKeys.timeline(projectId),
    queryFn: () =>
      apiClient
        .get<TimelinePoint[]>(`/vulnerabilities/timeline/${projectId}/`)
        .then((r) => r.data),
    enabled: projectId > 0,
    ...options,
  });
}

// ─── Scan Import hooks ───────────────────────────────────────────────────────

export function useScanImport(importId: number) {
  return useQuery<ScanImport>({
    queryKey: queryKeys.scanImport(importId),
    queryFn: () =>
      apiClient.get<ScanImport>(`/vulnerabilities/imports/${importId}/`).then((r) => r.data),
    enabled: importId > 0,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      return data.status === "pending" || data.status === "processing" ? 2000 : false;
    },
  });
}

export function useUploadScan(subprojectId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (formData: FormData) =>
      apiClient
        .post<ScanImport>(`/vulnerabilities/import/${subprojectId}/`, formData, {
          headers: { "Content-Type": "multipart/form-data" },
        })
        .then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.vulnerabilities(subprojectId) });
    },
  });
}

// ─── Report Export hooks ─────────────────────────────────────────────────────

export function useReportExports(
  subprojectId: number,
  options?: Partial<UseQueryOptions<ReportExport[]>>
) {
  return useQuery<ReportExport[]>({
    queryKey: queryKeys.reportExports(subprojectId),
    queryFn: () =>
      apiClient
        .get<ReportExport[]>("/reports/exports/", { params: { subproject: subprojectId } })
        .then((r) => r.data),
    enabled: subprojectId > 0,
    ...options,
  });
}

export function useReportExport(
  exportId: number,
  options?: Partial<UseQueryOptions<ReportExport>>
) {
  return useQuery<ReportExport>({
    queryKey: queryKeys.reportExport(exportId),
    queryFn: () =>
      apiClient.get<ReportExport>(`/reports/exports/${exportId}/`).then((r) => r.data),
    enabled: exportId > 0,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      return data.status === "pending" || data.status === "generating" ? 3000 : false;
    },
    ...options,
  });
}

export function useGenerateReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: {
      subproject: number;
      format: ReportFormat;
      risk_levels?: RiskLevel[];
      vuln_status?: VulnStatus[];
    }) =>
      apiClient.post<ReportExport>("/reports/generate/", data).then((r) => r.data),
    onSuccess: (report) => {
      qc.invalidateQueries({ queryKey: queryKeys.reportExports(report.subproject) });
    },
  });
}

// ─── Screenshots hooks ───────────────────────────────────────────────────────

export function useScreenshots(
  projectId: number,
  subprojectId: number,
  options?: Partial<UseQueryOptions<Screenshot[]>>
) {
  return useQuery<Screenshot[]>({
    queryKey: queryKeys.screenshots(subprojectId),
    queryFn: () =>
      apiClient
        .get<Screenshot[]>(`/projects/${projectId}/subprojects/${subprojectId}/screenshots/`)
        .then((r) => r.data),
    enabled: projectId > 0 && subprojectId > 0,
    ...options,
  });
}

export function useUploadScreenshot(projectId: number, subprojectId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (formData: FormData) =>
      apiClient
        .post<Screenshot>(
          `/projects/${projectId}/subprojects/${subprojectId}/screenshots/`,
          formData,
          { headers: { "Content-Type": "multipart/form-data" } }
        )
        .then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.screenshots(subprojectId) });
    },
  });
}

// ─── Organization hooks ──────────────────────────────────────────────────────

export function useUpdateOrganization() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: FormData | Partial<Organization>) =>
      apiClient
        .patch<Organization>("/auth/organization/", data, {
          headers:
            data instanceof FormData
              ? { "Content-Type": "multipart/form-data" }
              : { "Content-Type": "application/json" },
        })
        .then((r) => r.data),
    onSuccess: (org) => {
      qc.setQueryData(queryKeys.organization, org);
    },
  });
}

/**
 * Dashboard: license status summary, recent projects with lock status.
 */
import { Link } from "react-router-dom";
import {
  FolderOpen,
  Plus,
  Lock,
  Loader2,
  TrendingUp,
  ShieldAlert,
  Clock,
  CheckCircle2,
} from "lucide-react";
import { format } from "date-fns";
import { useAuthStore } from "@/store/authStore";
import { useProjects, useLicenseStatus } from "@/api/hooks";
import { Layout } from "@/components/Layout";
import type { LicenseStatus } from "@/api/types";

function LicenseCard({ license }: { license: LicenseStatus }) {
  const statusConfig = {
    trial_active: {
      label: "Trial Active",
      color: "text-green-400",
      bg: "bg-green-950 border-green-800",
      icon: <Clock className="h-5 w-5" />,
    },
    trial_expired: {
      label: "Trial Expired",
      color: "text-red-400",
      bg: "bg-red-950 border-red-800",
      icon: <ShieldAlert className="h-5 w-5" />,
    },
    pro_active: {
      label: "PRO Active",
      color: "text-blue-400",
      bg: "bg-blue-950 border-blue-800",
      icon: <CheckCircle2 className="h-5 w-5" />,
    },
    pro_expired: {
      label: "PRO Expired",
      color: "text-red-400",
      bg: "bg-red-950 border-red-800",
      icon: <ShieldAlert className="h-5 w-5" />,
    },
    invalid: {
      label: "Invalid License",
      color: "text-red-400",
      bg: "bg-red-950 border-red-800",
      icon: <ShieldAlert className="h-5 w-5" />,
    },
  };

  const cfg = statusConfig[license.status];

  return (
    <div className={`card border ${cfg.bg}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wide font-medium">
            License Status
          </p>
          <p className={`text-lg font-semibold mt-1 ${cfg.color} flex items-center gap-2`}>
            {cfg.icon}
            {cfg.label}
          </p>
          {license.days_remaining !== null && license.status === "trial_active" && (
            <p className="text-xs text-slate-400 mt-1">
              {license.days_remaining} day{license.days_remaining === 1 ? "" : "s"} remaining
            </p>
          )}
          {license.trial_expires_at && license.status !== "pro_active" && (
            <p className="text-xs text-slate-500 mt-0.5">
              Trial ends: {format(new Date(license.trial_expires_at), "MMM d, yyyy")}
            </p>
          )}
        </div>
        {license.status !== "pro_active" && (
          <Link to="/settings" className="btn-primary text-xs px-3 py-1.5 shrink-0">
            Upgrade to PRO
          </Link>
        )}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { user } = useAuthStore();
  const { data: license, isLoading: licenseLoading } = useLicenseStatus();
  const { data: projectsData, isLoading: projectsLoading } = useProjects({ page: 1 });

  const recentProjects = projectsData?.results.slice(0, 6) ?? [];
  const canCreate = license?.is_active ?? false;

  return (
    <Layout>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">
            Welcome back, {user?.full_name || user?.email}
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Here's what's happening with your security assessments.
          </p>
        </div>
        {canCreate && (
          <Link to="/projects" className="btn-primary">
            <Plus className="h-4 w-4" />
            New Project
          </Link>
        )}
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
        {licenseLoading ? (
          <div className="card flex items-center justify-center col-span-3 py-8">
            <Loader2 className="h-5 w-5 animate-spin text-slate-500" />
          </div>
        ) : license ? (
          <>
            <LicenseCard license={license} />
            <div className="card">
              <p className="text-xs text-slate-500 uppercase tracking-wide font-medium">
                Total Projects
              </p>
              <p className="text-3xl font-bold text-slate-100 mt-2">
                {projectsLoading ? "—" : projectsData?.count ?? 0}
              </p>
            </div>
            <div className="card">
              <p className="text-xs text-slate-500 uppercase tracking-wide font-medium flex items-center gap-1">
                <TrendingUp className="h-3.5 w-3.5" />
                Capabilities
              </p>
              <div className="mt-2 space-y-1 text-xs">
                <p className={license.is_active ? "text-green-400" : "text-red-400"}>
                  {license.is_active ? "✓" : "✗"} Create projects
                </p>
                <p className={license.is_active ? "text-green-400" : "text-red-400"}>
                  {license.is_active ? "✓" : "✗"} Export reports
                </p>
                <p className={license.is_active ? "text-green-400" : "text-red-400"}>
                  {license.is_active ? "✓" : "✗"} Import scans
                </p>
              </div>
            </div>
          </>
        ) : null}
      </div>

      {/* Recent Projects */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-slate-100">Recent Projects</h2>
          <Link to="/projects" className="text-sm text-blue-400 hover:text-blue-300">
            View all
          </Link>
        </div>

        {projectsLoading ? (
          <div className="flex items-center justify-center py-16 text-slate-500">
            <Loader2 className="h-5 w-5 animate-spin mr-2" />
            Loading projects…
          </div>
        ) : recentProjects.length === 0 ? (
          <div className="card text-center py-12">
            <FolderOpen className="h-12 w-12 text-slate-700 mx-auto mb-4" />
            <p className="text-slate-400 font-medium">No projects yet</p>
            <p className="text-slate-500 text-sm mt-1">
              Create your first security assessment project to get started.
            </p>
            {canCreate && (
              <Link to="/projects" className="btn-primary mt-4 inline-flex">
                <Plus className="h-4 w-4" />
                Create Project
              </Link>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {recentProjects.map((project) => {
              const isLocked = project.lock && !project.lock.is_expired;
              return (
                <Link
                  key={project.id}
                  to={`/projects/${project.id}`}
                  className="card hover:border-blue-700 transition-colors group block"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <h3 className="font-semibold text-slate-100 group-hover:text-blue-400 transition-colors truncate">
                        {project.title}
                      </h3>
                      <p className="text-sm text-slate-400 mt-0.5 truncate">
                        {project.client_name}
                      </p>
                    </div>
                    {isLocked && (
                      <Lock className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
                    )}
                  </div>
                  <div className="mt-3 flex items-center gap-3 text-xs text-slate-500">
                    <span>
                      {project.subproject_count} scan
                      {project.subproject_count !== 1 ? "s" : ""}
                    </span>
                    <span>·</span>
                    <span>{format(new Date(project.updated_at), "MMM d, yyyy")}</span>
                  </div>
                  {isLocked && (
                    <p className="mt-2 text-xs text-amber-500">
                      Locked by {project.lock?.locked_by_name}
                    </p>
                  )}
                </Link>
              );
            })}
          </div>
        )}
      </div>
    </Layout>
  );
}

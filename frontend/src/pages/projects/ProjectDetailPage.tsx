/**
 * Project detail page with tabs: Overview, SubProjects, Settings.
 * Acquires a lock on mount, sends heartbeat every 60s, releases on leave.
 */
import { useEffect, useRef, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import {
  Plus,
  Loader2,
  Settings,
  LayoutList,
  Eye,
  Trash2,
  Save,
  Calendar,
  Users,
  RefreshCw,
} from "lucide-react";
import { format } from "date-fns";
import toast from "react-hot-toast";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  useProject,
  useSubProjects,
  useAcquireLock,
  useHeartbeat,
  useReleaseLock,
  useUpdateProject,
  useCreateSubProject,
  useDeleteSubProject,
  useInviteUser,
  useUsers,
} from "@/api/hooks";
import { Layout } from "@/components/Layout";
import { ProjectLockBanner } from "@/components/ProjectLockBanner";

type Tab = "overview" | "subprojects" | "settings";

// ─── Invite User Modal ────────────────────────────────────────────────────────

function InviteModal({ onClose }: { onClose: () => void }) {
  const invite = useInviteUser();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"admin" | "member">("member");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    try {
      await invite.mutateAsync({ email, role });
      toast.success(`Invitation sent to ${email}`);
      onClose();
    } catch {
      toast.error("Failed to send invitation.");
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="card w-full max-w-md">
        <h3 className="text-lg font-semibold text-slate-100 mb-4">Invite Team Member</h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="label">Email address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="input"
              placeholder="colleague@company.com"
              required
            />
          </div>
          <div>
            <label className="label">Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as "admin" | "member")}
              className="input"
            >
              <option value="member">Member (read + edit)</option>
              <option value="admin">Admin (full access)</option>
            </select>
          </div>
          <div className="flex gap-3">
            <button type="button" onClick={onClose} className="btn-secondary flex-1">
              Cancel
            </button>
            <button type="submit" disabled={invite.isPending} className="btn-primary flex-1">
              {invite.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Send Invite"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Create SubProject Modal ──────────────────────────────────────────────────

const spSchema = z.object({
  title: z.string().min(1, "Title is required"),
  description: z.string().optional(),
  scan_date: z.string().min(1, "Scan date is required"),
});

type SpFormData = z.infer<typeof spSchema>;

function CreateSubProjectModal({
  projectId,
  onClose,
}: {
  projectId: number;
  onClose: () => void;
}) {
  const create = useCreateSubProject(projectId);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SpFormData>({
    resolver: zodResolver(spSchema),
    defaultValues: { scan_date: format(new Date(), "yyyy-MM-dd") },
  });

  async function onSubmit(data: SpFormData) {
    try {
      await create.mutateAsync(data);
      toast.success("Sub-project created!");
      onClose();
    } catch {
      toast.error("Failed to create sub-project.");
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="card w-full max-w-md">
        <h3 className="text-lg font-semibold text-slate-100 mb-4">New Sub-Project</h3>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div>
            <label className="label">Title</label>
            <input {...register("title")} className="input" placeholder="Q1 2025 Scan" />
            {errors.title && <p className="mt-1 text-xs text-red-400">{errors.title.message}</p>}
          </div>
          <div>
            <label className="label">Description</label>
            <textarea {...register("description")} className="input min-h-[80px] resize-y" />
          </div>
          <div>
            <label className="label">Scan date</label>
            <input {...register("scan_date")} type="date" className="input" />
            {errors.scan_date && (
              <p className="mt-1 text-xs text-red-400">{errors.scan_date.message}</p>
            )}
          </div>
          <div className="flex gap-3">
            <button type="button" onClick={onClose} className="btn-secondary flex-1">
              Cancel
            </button>
            <button type="submit" disabled={isSubmitting} className="btn-primary flex-1">
              {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : "Create"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Settings form ────────────────────────────────────────────────────────────

const settingsSchema = z.object({
  title: z.string().min(1, "Title required"),
  description: z.string().optional(),
  client_name: z.string().min(1, "Client name required"),
  client_contact: z.string().optional(),
  client_email: z.string().email("Invalid email").optional().or(z.literal("")),
  template: z.string().optional(),
  font_family: z.string().optional(),
  primary_color: z.string().optional(),
  secondary_color: z.string().optional(),
  watermark_text: z.string().optional(),
  header_left: z.string().optional(),
  header_center: z.string().optional(),
  footer_text: z.string().optional(),
});

type SettingsFormData = z.infer<typeof settingsSchema>;

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const projectId = Number(id);
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<Tab>("overview");
  const [showCreateSp, setShowCreateSp] = useState(false);
  const [showInvite, setShowInvite] = useState(false);

  const { data: project, isLoading, refetch } = useProject(projectId);
  const { data: subprojects } = useSubProjects(projectId);
  const { data: teamUsers } = useUsers();

  const acquire = useAcquireLock(projectId);
  const heartbeat = useHeartbeat(projectId);
  const release = useReleaseLock(projectId);
  const updateProject = useUpdateProject(projectId);
  const deleteSubProject = useDeleteSubProject(projectId);

  const heartbeatInterval = useRef<ReturnType<typeof setInterval> | null>(null);
  const hasLock = useRef(false);

  // Determine if locked by someone else (we tried to acquire but couldn't)
  const currentLock = project?.lock;
  const isLockedByOther =
    currentLock &&
    !currentLock.is_expired &&
    !hasLock.current;

  // Acquire lock on mount, release on unmount
  useEffect(() => {
    if (!projectId) return;

    async function acquireLockAndStartHeartbeat() {
      try {
        await acquire.mutateAsync();
        hasLock.current = true;
        heartbeatInterval.current = setInterval(() => {
          heartbeat.mutate();
        }, 60_000);
      } catch {
        // Could not acquire — another user has it
      }
    }

    acquireLockAndStartHeartbeat();

    return () => {
      if (heartbeatInterval.current) {
        clearInterval(heartbeatInterval.current);
      }
      if (hasLock.current) {
        release.mutate();
        hasLock.current = false;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  const {
    register,
    handleSubmit,
    formState: { errors: settingsErrors, isSubmitting: isSettingsSubmitting, isDirty },
    reset,
  } = useForm<SettingsFormData>({
    resolver: zodResolver(settingsSchema),
    values: project
      ? {
          title: project.title,
          description: project.description,
          client_name: project.client_name,
          client_contact: project.client_contact,
          client_email: project.client_email,
          template: project.template,
          font_family: project.font_family,
          primary_color: project.primary_color,
          secondary_color: project.secondary_color,
          watermark_text: project.watermark_text,
          header_left: project.header_left,
          header_center: project.header_center,
          footer_text: project.footer_text,
        }
      : undefined,
  });

  async function onSaveSettings(data: SettingsFormData) {
    try {
      await updateProject.mutateAsync(data);
      toast.success("Project settings saved.");
      reset(data);
    } catch {
      toast.error("Failed to save settings.");
    }
  }

  async function handleDeleteSubProject(spId: number, spTitle: string) {
    if (!confirm(`Delete "${spTitle}"? This will remove all vulnerabilities and exports.`)) return;
    try {
      await deleteSubProject.mutateAsync(spId);
      toast.success("Sub-project deleted.");
    } catch {
      toast.error("Failed to delete sub-project.");
    }
  }

  const TABS = [
    { key: "overview" as Tab, label: "Overview", icon: <Eye className="h-4 w-4" /> },
    { key: "subprojects" as Tab, label: "Sub-Projects", icon: <LayoutList className="h-4 w-4" /> },
    { key: "settings" as Tab, label: "Settings", icon: <Settings className="h-4 w-4" /> },
  ];

  if (isLoading) {
    return (
      <Layout>
        <div className="flex items-center justify-center py-20 text-slate-500">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          Loading project…
        </div>
      </Layout>
    );
  }

  if (!project) {
    return (
      <Layout>
        <div className="text-center py-20">
          <p className="text-slate-400">Project not found.</p>
          <button onClick={() => navigate("/projects")} className="btn-primary mt-4">
            Back to Projects
          </button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      {showCreateSp && (
        <CreateSubProjectModal
          projectId={projectId}
          onClose={() => setShowCreateSp(false)}
        />
      )}
      {showInvite && <InviteModal onClose={() => setShowInvite(false)} />}

      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-500 mb-4">
        <Link to="/projects" className="hover:text-slate-300">
          Projects
        </Link>
        <span>/</span>
        <span className="text-slate-300">{project.title}</span>
      </div>

      {/* Lock banner */}
      {isLockedByOther && currentLock && (
        <div className="mb-4">
          <ProjectLockBanner lock={currentLock} />
        </div>
      )}

      {/* Page header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">{project.title}</h1>
          <p className="text-slate-400 text-sm mt-1">{project.client_name}</p>
          {project.description && (
            <p className="text-slate-500 text-sm mt-1 max-w-2xl">{project.description}</p>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => refetch()}
            className="btn-ghost p-2"
            aria-label="Refresh"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
          <button onClick={() => setShowInvite(true)} className="btn-secondary">
            <Users className="h-4 w-4" />
            Invite
          </button>
          <button onClick={() => setShowCreateSp(true)} className="btn-primary">
            <Plus className="h-4 w-4" />
            Add Scan
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-slate-800 mb-6">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.key
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Project info */}
          <div className="lg:col-span-2 space-y-4">
            <div className="card">
              <h3 className="font-semibold text-slate-100 mb-4">Project Details</h3>
              <dl className="space-y-3">
                <div className="flex gap-4">
                  <dt className="text-sm text-slate-500 w-32 shrink-0">Client</dt>
                  <dd className="text-sm text-slate-200">{project.client_name}</dd>
                </div>
                {project.client_contact && (
                  <div className="flex gap-4">
                    <dt className="text-sm text-slate-500 w-32 shrink-0">Contact</dt>
                    <dd className="text-sm text-slate-200">{project.client_contact}</dd>
                  </div>
                )}
                {project.client_email && (
                  <div className="flex gap-4">
                    <dt className="text-sm text-slate-500 w-32 shrink-0">Email</dt>
                    <dd className="text-sm text-slate-200">{project.client_email}</dd>
                  </div>
                )}
                <div className="flex gap-4">
                  <dt className="text-sm text-slate-500 w-32 shrink-0 flex items-center gap-1">
                    <Calendar className="h-3.5 w-3.5" />
                    Start Date
                  </dt>
                  <dd className="text-sm text-slate-200">
                    {format(new Date(project.start_date), "MMMM d, yyyy")}
                  </dd>
                </div>
                <div className="flex gap-4">
                  <dt className="text-sm text-slate-500 w-32 shrink-0">Template</dt>
                  <dd className="text-sm text-slate-200">{project.template || "Default"}</dd>
                </div>
                <div className="flex gap-4">
                  <dt className="text-sm text-slate-500 w-32 shrink-0">Font</dt>
                  <dd className="text-sm text-slate-200">{project.font_family || "Inter"}</dd>
                </div>
              </dl>
            </div>

            {/* Sub-projects summary */}
            <div className="card">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold text-slate-100">Scans ({project.subproject_count})</h3>
                <button
                  onClick={() => setActiveTab("subprojects")}
                  className="text-xs text-blue-400 hover:text-blue-300"
                >
                  View all
                </button>
              </div>
              {!subprojects || subprojects.length === 0 ? (
                <p className="text-slate-500 text-sm">No scans yet. Add a sub-project to get started.</p>
              ) : (
                <div className="space-y-2">
                  {subprojects.slice(0, 3).map((sp) => (
                    <div key={sp.id} className="flex items-center justify-between">
                      <div>
                        <Link
                          to={`/projects/${projectId}/subprojects/${sp.id}`}
                          className="text-sm font-medium text-slate-200 hover:text-blue-400"
                        >
                          {sp.title}
                        </Link>
                        <p className="text-xs text-slate-500">
                          {format(new Date(sp.scan_date), "MMM d, yyyy")} ·{" "}
                          {sp.vulnerability_count} findings
                        </p>
                      </div>
                      <span className="text-xs text-slate-500">{sp.open_count} open</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Team */}
          <div className="card h-fit">
            <h3 className="font-semibold text-slate-100 mb-4">Team</h3>
            {teamUsers && teamUsers.length > 0 ? (
              <div className="space-y-3">
                {teamUsers.map((u) => (
                  <div key={u.id} className="flex items-center gap-3">
                    <div className="h-8 w-8 rounded-full bg-blue-700 flex items-center justify-center text-xs font-medium text-white">
                      {u.first_name?.[0] ?? u.email[0].toUpperCase()}
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-slate-200 truncate">
                        {u.first_name} {u.last_name}
                      </p>
                      <p className="text-xs text-slate-500 truncate">{u.role}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-slate-500 text-sm">No team members yet.</p>
            )}
            <button
              onClick={() => setShowInvite(true)}
              className="btn-secondary w-full mt-4 text-sm"
            >
              <Plus className="h-3.5 w-3.5" />
              Invite member
            </button>
          </div>
        </div>
      )}

      {activeTab === "subprojects" && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-slate-100">
              Sub-Projects ({subprojects?.length ?? 0})
            </h2>
            <button onClick={() => setShowCreateSp(true)} className="btn-primary">
              <Plus className="h-4 w-4" />
              Add Scan
            </button>
          </div>

          {!subprojects || subprojects.length === 0 ? (
            <div className="card text-center py-12">
              <LayoutList className="h-10 w-10 text-slate-700 mx-auto mb-3" />
              <p className="text-slate-400">No sub-projects yet.</p>
              <p className="text-slate-500 text-sm mt-1">
                Create a sub-project for each scan or engagement phase.
              </p>
              <button onClick={() => setShowCreateSp(true)} className="btn-primary mt-4 inline-flex">
                <Plus className="h-4 w-4" />
                Create Sub-Project
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {subprojects.map((sp) => (
                <div key={sp.id} className="card flex items-center gap-4">
                  <div className="flex-1 min-w-0">
                    <Link
                      to={`/projects/${projectId}/subprojects/${sp.id}`}
                      className="font-medium text-slate-100 hover:text-blue-400 transition-colors"
                    >
                      {sp.title}
                    </Link>
                    <div className="flex items-center gap-3 mt-1 text-xs text-slate-500 flex-wrap">
                      <span>{format(new Date(sp.scan_date), "MMM d, yyyy")}</span>
                      <span>·</span>
                      <span>{sp.vulnerability_count} findings</span>
                      {sp.critical_count > 0 && (
                        <>
                          <span>·</span>
                          <span className="text-red-400">{sp.critical_count} critical</span>
                        </>
                      )}
                      {sp.high_count > 0 && (
                        <>
                          <span>·</span>
                          <span className="text-orange-400">{sp.high_count} high</span>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Link
                      to={`/projects/${projectId}/subprojects/${sp.id}`}
                      className="btn-secondary text-xs py-1.5"
                    >
                      Open
                    </Link>
                    <button
                      onClick={() => handleDeleteSubProject(sp.id, sp.title)}
                      className="btn-ghost text-red-400 hover:text-red-300 hover:bg-red-950 p-2"
                      aria-label="Delete sub-project"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === "settings" && (
        <form onSubmit={handleSubmit(onSaveSettings)} className="space-y-6 max-w-2xl">
          <div className="card space-y-4">
            <h3 className="font-semibold text-slate-100">Basic Info</h3>
            <div>
              <label className="label">Project title</label>
              <input {...register("title")} className="input" />
              {settingsErrors.title && (
                <p className="mt-1 text-xs text-red-400">{settingsErrors.title.message}</p>
              )}
            </div>
            <div>
              <label className="label">Description</label>
              <textarea {...register("description")} className="input min-h-[80px] resize-y" />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label">Client name</label>
                <input {...register("client_name")} className="input" />
              </div>
              <div>
                <label className="label">Client contact</label>
                <input {...register("client_contact")} className="input" />
              </div>
            </div>
            <div>
              <label className="label">Client email</label>
              <input {...register("client_email")} type="email" className="input" />
            </div>
          </div>

          <div className="card space-y-4">
            <h3 className="font-semibold text-slate-100">Report Appearance</h3>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label">Template</label>
                <select {...register("template")} className="input">
                  <option value="">Default</option>
                  <option value="executive">Executive</option>
                  <option value="technical">Technical</option>
                  <option value="minimal">Minimal</option>
                </select>
              </div>
              <div>
                <label className="label">Font family</label>
                <select {...register("font_family")} className="input">
                  <option value="Inter">Inter</option>
                  <option value="Roboto">Roboto</option>
                  <option value="Source Sans Pro">Source Sans Pro</option>
                  <option value="Noto Sans">Noto Sans</option>
                </select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label">Primary color</label>
                <input {...register("primary_color")} type="color" className="input h-10 p-1 cursor-pointer" />
              </div>
              <div>
                <label className="label">Secondary color</label>
                <input {...register("secondary_color")} type="color" className="input h-10 p-1 cursor-pointer" />
              </div>
            </div>
            <div>
              <label className="label">Watermark text</label>
              <input {...register("watermark_text")} className="input" placeholder="CONFIDENTIAL" />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label">Header left</label>
                <input {...register("header_left")} className="input" placeholder="Company logo area" />
              </div>
              <div>
                <label className="label">Header center</label>
                <input {...register("header_center")} className="input" placeholder="Report title" />
              </div>
            </div>
            <div>
              <label className="label">Footer text</label>
              <input {...register("footer_text")} className="input" placeholder="Confidential — For authorized use only" />
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={isSettingsSubmitting || !isDirty}
              className="btn-primary"
            >
              {isSettingsSubmitting ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              Save Settings
            </button>
            {isDirty && (
              <span className="text-xs text-amber-400">You have unsaved changes</span>
            )}
          </div>
        </form>
      )}
    </Layout>
  );
}

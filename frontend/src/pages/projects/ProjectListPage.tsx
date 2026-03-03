/**
 * Paginated project list with search, create button (if licensed),
 * lock indicators, and client info.
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Plus,
  Search,
  FolderOpen,
  Lock,
  Loader2,
  ChevronLeft,
  ChevronRight,
  Trash2,
} from "lucide-react";
import { format } from "date-fns";
import toast from "react-hot-toast";
import { useProjects, useLicenseStatus, useDeleteProject, useCreateProject } from "@/api/hooks";
import { Layout } from "@/components/Layout";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

const PAGE_SIZE = 12;

// ─── Create Project Modal ─────────────────────────────────────────────────────

const createSchema = z.object({
  title: z.string().min(1, "Title is required"),
  description: z.string().optional(),
  client_name: z.string().min(1, "Client name is required"),
  client_contact: z.string().optional(),
  client_email: z.string().email("Enter valid email").optional().or(z.literal("")),
  start_date: z.string().min(1, "Start date is required"),
});

type CreateFormData = z.infer<typeof createSchema>;

interface CreateProjectModalProps {
  onClose: () => void;
}

function CreateProjectModal({ onClose }: CreateProjectModalProps) {
  const createProject = useCreateProject();
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<CreateFormData>({
    resolver: zodResolver(createSchema),
    defaultValues: { start_date: format(new Date(), "yyyy-MM-dd") },
  });

  async function onSubmit(data: CreateFormData) {
    try {
      await createProject.mutateAsync(data);
      toast.success("Project created successfully!");
      onClose();
    } catch {
      toast.error("Failed to create project.");
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="card w-full max-w-lg">
        <h2 className="text-xl font-semibold text-slate-100 mb-6">New Project</h2>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div>
            <label className="label">Project title</label>
            <input {...register("title")} className="input" placeholder="Q1 2025 Pentest" />
            {errors.title && <p className="mt-1 text-xs text-red-400">{errors.title.message}</p>}
          </div>
          <div>
            <label className="label">Description</label>
            <textarea
              {...register("description")}
              className="input min-h-[80px] resize-y"
              placeholder="Brief description of the engagement…"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label">Client name</label>
              <input {...register("client_name")} className="input" placeholder="Acme Corp" />
              {errors.client_name && (
                <p className="mt-1 text-xs text-red-400">{errors.client_name.message}</p>
              )}
            </div>
            <div>
              <label className="label">Start date</label>
              <input {...register("start_date")} type="date" className="input" />
              {errors.start_date && (
                <p className="mt-1 text-xs text-red-400">{errors.start_date.message}</p>
              )}
            </div>
          </div>
          <div>
            <label className="label">Client contact person</label>
            <input {...register("client_contact")} className="input" placeholder="John Doe" />
          </div>
          <div>
            <label className="label">Client email</label>
            <input {...register("client_email")} type="email" className="input" placeholder="john@acme.com" />
            {errors.client_email && (
              <p className="mt-1 text-xs text-red-400">{errors.client_email.message}</p>
            )}
          </div>
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary flex-1">
              Cancel
            </button>
            <button type="submit" disabled={isSubmitting} className="btn-primary flex-1">
              {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : "Create Project"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ProjectListPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [showCreateModal, setShowCreateModal] = useState(false);

  const { data: license } = useLicenseStatus();
  const { data, isLoading } = useProjects({ search, page });
  const deleteProject = useDeleteProject();

  const totalPages = data ? Math.ceil(data.count / PAGE_SIZE) : 1;
  const canCreate = license?.is_active ?? false;

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setSearch(searchInput);
    setPage(1);
  }

  async function handleDelete(id: number, title: string) {
    if (!confirm(`Delete project "${title}"? This cannot be undone.`)) return;
    try {
      await deleteProject.mutateAsync(id);
      toast.success("Project deleted.");
    } catch {
      toast.error("Failed to delete project.");
    }
  }

  return (
    <Layout>
      {showCreateModal && (
        <CreateProjectModal onClose={() => setShowCreateModal(false)} />
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <h1 className="text-2xl font-bold text-slate-100">Projects</h1>
        <div className="flex items-center gap-3">
          {/* Search */}
          <form onSubmit={handleSearch} className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <input
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                className="input pl-9 w-48 sm:w-64"
                placeholder="Search projects…"
              />
            </div>
            <button type="submit" className="btn-secondary">
              Search
            </button>
          </form>
          {canCreate && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="btn-primary shrink-0"
            >
              <Plus className="h-4 w-4" />
              New Project
            </button>
          )}
        </div>
      </div>

      {/* List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20 text-slate-500">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          Loading projects…
        </div>
      ) : !data || data.results.length === 0 ? (
        <div className="card text-center py-16">
          <FolderOpen className="h-12 w-12 text-slate-700 mx-auto mb-4" />
          <p className="text-slate-400 font-medium">
            {search ? `No projects matching "${search}"` : "No projects yet"}
          </p>
          {canCreate && !search && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="btn-primary mt-4 inline-flex"
            >
              <Plus className="h-4 w-4" />
              Create your first project
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {data.results.map((project) => {
            const isLocked = project.lock && !project.lock.is_expired;
            return (
              <div
                key={project.id}
                className="card hover:border-blue-700 transition-colors flex items-center gap-4"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <Link
                      to={`/projects/${project.id}`}
                      className="font-semibold text-slate-100 hover:text-blue-400 transition-colors truncate"
                    >
                      {project.title}
                    </Link>
                    {isLocked && (
                      <Lock className="h-3.5 w-3.5 text-amber-500 shrink-0" />
                    )}
                  </div>
                  <div className="flex items-center gap-3 mt-1 text-sm text-slate-400 flex-wrap">
                    <span className="truncate">{project.client_name}</span>
                    <span className="text-slate-600">·</span>
                    <span>
                      {project.subproject_count} scan{project.subproject_count !== 1 ? "s" : ""}
                    </span>
                    <span className="text-slate-600">·</span>
                    <span>{format(new Date(project.updated_at), "MMM d, yyyy")}</span>
                    {isLocked && (
                      <>
                        <span className="text-slate-600">·</span>
                        <span className="text-amber-500 text-xs">
                          Locked by {project.lock?.locked_by_name}
                        </span>
                      </>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <Link to={`/projects/${project.id}`} className="btn-secondary text-xs py-1.5">
                    Open
                  </Link>
                  <button
                    onClick={() => handleDelete(project.id, project.title)}
                    className="btn-ghost text-red-400 hover:text-red-300 hover:bg-red-950 p-2"
                    aria-label="Delete project"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-6">
          <p className="text-sm text-slate-500">
            Page {page} of {totalPages} ({data?.count ?? 0} total)
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="btn-secondary py-1.5 px-3"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="btn-secondary py-1.5 px-3"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </Layout>
  );
}

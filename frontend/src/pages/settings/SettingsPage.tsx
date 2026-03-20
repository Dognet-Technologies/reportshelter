/**
 * Settings page: organization profile, logo upload, colors, legal disclaimer,
 * and license activation form.
 */
import { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
import {
  Loader2,
  Save,
  Upload,
  Building2,
  Shield,
  CheckCircle2,
  AlertCircle,
  Clock,
  Key,
  User,
  Lock,
  Eye,
  EyeOff,
} from "lucide-react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { format } from "date-fns";
import toast from "react-hot-toast";
import {
  useMe,
  useUpdateMe,
  useChangePassword,
  useOrganization,
  useUpdateOrganization,
  useLicenseStatus,
  useActivateLicense,
} from "@/api/hooks";
import { Layout } from "@/components/Layout";
import { useAuthStore } from "@/store/authStore";
import type { LicenseStatusCode } from "@/api/types";

// ─── Profile Section ──────────────────────────────────────────────────────────

const profileSchema = z.object({
  first_name: z.string().min(1, "First name is required"),
  last_name: z.string().min(1, "Last name is required"),
  email: z.string().email("Enter a valid email address"),
});

type ProfileFormData = z.infer<typeof profileSchema>;

const passwordSchema = z
  .object({
    current_password: z.string().min(1, "Current password is required"),
    new_password: z
      .string()
      .min(12, "Password must be at least 12 characters")
      .regex(/[A-Z]/, "Must contain at least one uppercase letter")
      .regex(/[0-9]/, "Must contain at least one number"),
    confirm_password: z.string().min(1, "Please confirm your password"),
  })
  .refine((d) => d.new_password === d.confirm_password, {
    message: "Passwords do not match",
    path: ["confirm_password"],
  });

type PasswordFormData = z.infer<typeof passwordSchema>;

function ProfileSection() {
  const { data: me, isLoading } = useMe();
  const updateMe = useUpdateMe();
  const changePassword = useChangePassword();
  const { setUser } = useAuthStore();
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const {
    register: regProfile,
    handleSubmit: handleProfile,
    formState: { errors: profileErrors, isSubmitting: profileSubmitting, isDirty: profileDirty },
    reset: resetProfile,
  } = useForm<ProfileFormData>({
    resolver: zodResolver(profileSchema),
    values: me
      ? { first_name: me.first_name, last_name: me.last_name, email: me.email }
      : undefined,
  });

  const {
    register: regPwd,
    handleSubmit: handlePwd,
    formState: { errors: pwdErrors, isSubmitting: pwdSubmitting },
    reset: resetPwd,
    setError: setPwdError,
  } = useForm<PasswordFormData>({ resolver: zodResolver(passwordSchema) });

  async function onSaveProfile(data: ProfileFormData) {
    try {
      const updated = await updateMe.mutateAsync(data);
      setUser(updated);
      toast.success("Profile updated.");
      resetProfile(data);
    } catch {
      toast.error("Failed to update profile.");
    }
  }

  async function onChangePassword(data: PasswordFormData) {
    try {
      await changePassword.mutateAsync(data);
      toast.success("Password changed successfully.");
      resetPwd();
    } catch (err: unknown) {
      const axiosErr = err as {
        response?: { data?: { errors?: Record<string, string[]>; error?: string } };
      };
      const fieldErrors = axiosErr.response?.data?.errors;
      if (fieldErrors) {
        Object.entries(fieldErrors).forEach(([field, messages]) => {
          setPwdError(field as keyof PasswordFormData, { message: messages[0] });
        });
      } else {
        setPwdError("root", {
          message: axiosErr.response?.data?.error ?? "Failed to change password.",
        });
      }
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8 text-slate-500">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        Loading…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Personal info */}
      <form onSubmit={handleProfile(onSaveProfile)} className="card space-y-4">
        <h3 className="font-semibold text-slate-100 flex items-center gap-2">
          <User className="h-4 w-4" />
          Personal Information
        </h3>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label">First name</label>
            <input {...regProfile("first_name")} className="input" />
            {profileErrors.first_name && (
              <p className="mt-1 text-xs text-red-400">{profileErrors.first_name.message}</p>
            )}
          </div>
          <div>
            <label className="label">Last name</label>
            <input {...regProfile("last_name")} className="input" />
            {profileErrors.last_name && (
              <p className="mt-1 text-xs text-red-400">{profileErrors.last_name.message}</p>
            )}
          </div>
        </div>

        <div>
          <label className="label">Email address</label>
          <input {...regProfile("email")} type="email" className="input" />
          {profileErrors.email && (
            <p className="mt-1 text-xs text-red-400">{profileErrors.email.message}</p>
          )}
          <p className="mt-1 text-xs text-slate-500">
            Changing your email will require re-verification.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={profileSubmitting || !profileDirty}
            className="btn-primary"
          >
            {profileSubmitting ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            Save Profile
          </button>
          {profileDirty && (
            <span className="text-xs text-amber-400">You have unsaved changes</span>
          )}
        </div>
      </form>

      {/* Change password */}
      <form onSubmit={handlePwd(onChangePassword)} className="card space-y-4">
        <h3 className="font-semibold text-slate-100 flex items-center gap-2">
          <Lock className="h-4 w-4" />
          Change Password
        </h3>

        {pwdErrors.root && (
          <div className="rounded-md border border-red-700 bg-red-950 px-4 py-3 text-sm text-red-300">
            {pwdErrors.root.message}
          </div>
        )}

        <div>
          <label className="label">Current password</label>
          <div className="relative">
            <input
              {...regPwd("current_password")}
              type={showCurrent ? "text" : "password"}
              autoComplete="current-password"
              className="input pr-10"
              placeholder="••••••••"
            />
            <button
              type="button"
              onClick={() => setShowCurrent((v) => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              aria-label={showCurrent ? "Hide" : "Show"}
            >
              {showCurrent ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          {pwdErrors.current_password && (
            <p className="mt-1 text-xs text-red-400">{pwdErrors.current_password.message}</p>
          )}
        </div>

        <div>
          <label className="label">New password</label>
          <div className="relative">
            <input
              {...regPwd("new_password")}
              type={showNew ? "text" : "password"}
              autoComplete="new-password"
              className="input pr-10"
              placeholder="Min. 12 characters"
            />
            <button
              type="button"
              onClick={() => setShowNew((v) => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              aria-label={showNew ? "Hide" : "Show"}
            >
              {showNew ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          {pwdErrors.new_password && (
            <p className="mt-1 text-xs text-red-400">{pwdErrors.new_password.message}</p>
          )}
          <p className="mt-1 text-xs text-slate-500">
            At least 12 characters, one uppercase letter, one number.
          </p>
        </div>

        <div>
          <label className="label">Confirm new password</label>
          <div className="relative">
            <input
              {...regPwd("confirm_password")}
              type={showConfirm ? "text" : "password"}
              autoComplete="new-password"
              className="input pr-10"
              placeholder="••••••••"
            />
            <button
              type="button"
              onClick={() => setShowConfirm((v) => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              aria-label={showConfirm ? "Hide" : "Show"}
            >
              {showConfirm ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          {pwdErrors.confirm_password && (
            <p className="mt-1 text-xs text-red-400">{pwdErrors.confirm_password.message}</p>
          )}
        </div>

        <button type="submit" disabled={pwdSubmitting} className="btn-primary">
          {pwdSubmitting ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Lock className="h-4 w-4" />
          )}
          Change Password
        </button>
      </form>
    </div>
  );
}

// ─── Organization Form ────────────────────────────────────────────────────────

const orgSchema = z.object({
  name: z.string().min(1, "Organization name is required"),
  address: z.string().optional(),
  vat_number: z.string().optional(),
  website: z.string().url("Enter a valid URL").optional().or(z.literal("")),
  phone: z.string().optional(),
  legal_disclaimer: z.string().optional(),
  primary_color: z.string().optional(),
  secondary_color: z.string().optional(),
});

type OrgFormData = z.infer<typeof orgSchema>;

function OrganizationSection() {
  const { data: org, isLoading } = useOrganization();
  const updateOrg = useUpdateOrganization();
  const [logoFile, setLogoFile] = useState<File | null>(null);
  const [logoPreview, setLogoPreview] = useState<string | null>(null);

  const onDropLogo = useCallback((files: File[]) => {
    const file = files[0];
    if (!file) return;
    setLogoFile(file);
    setLogoPreview(URL.createObjectURL(file));
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop: onDropLogo,
    accept: { "image/png": [], "image/svg+xml": [], "image/jpeg": [] },
    maxFiles: 1,
  });

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting, isDirty },
    reset,
  } = useForm<OrgFormData>({
    resolver: zodResolver(orgSchema),
    values: org
      ? {
          name: org.name,
          address: org.address,
          vat_number: org.vat_number,
          website: org.website,
          phone: org.phone,
          legal_disclaimer: org.legal_disclaimer,
          primary_color: org.primary_color,
          secondary_color: org.secondary_color,
        }
      : undefined,
  });

  async function onSubmit(data: OrgFormData) {
    try {
      if (logoFile) {
        const formData = new FormData();
        Object.entries(data).forEach(([k, v]) => {
          if (v !== undefined && v !== null) formData.append(k, v);
        });
        formData.append("logo", logoFile);
        await updateOrg.mutateAsync(formData);
      } else {
        await updateOrg.mutateAsync(data);
      }
      toast.success("Organization settings saved.");
      reset(data);
      setLogoFile(null);
    } catch {
      toast.error("Failed to save organization settings.");
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8 text-slate-500">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        Loading…
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
      <div className="card space-y-4">
        <h3 className="font-semibold text-slate-100 flex items-center gap-2">
          <Building2 className="h-4 w-4" />
          Company Profile
        </h3>

        {/* Logo upload */}
        <div>
          <label className="label">Company Logo</label>
          <div className="flex items-start gap-4">
            <div
              {...getRootProps()}
              className={`rounded-lg border-2 border-dashed p-4 cursor-pointer transition-colors w-32 h-32 flex items-center justify-center ${
                isDragActive ? "border-blue-500 bg-blue-950/30" : "border-slate-700 hover:border-slate-500"
              }`}
            >
              <input {...getInputProps()} />
              {logoPreview || org?.logo ? (
                <img
                  src={logoPreview ?? org?.logo ?? ""}
                  alt="Company logo"
                  className="max-h-full max-w-full object-contain"
                />
              ) : (
                <div className="text-center text-slate-500">
                  <Upload className="h-6 w-6 mx-auto mb-1" />
                  <p className="text-xs">Upload</p>
                </div>
              )}
            </div>
            <div className="text-xs text-slate-500 space-y-1">
              <p>Supported formats: PNG, SVG, JPG</p>
              <p>Recommended: 400x200px, transparent background</p>
              <p>This logo appears in all generated reports.</p>
            </div>
          </div>
        </div>

        <div>
          <label className="label">Organization name</label>
          <input {...register("name")} className="input" />
          {errors.name && <p className="mt-1 text-xs text-red-400">{errors.name.message}</p>}
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label">Phone</label>
            <input {...register("phone")} type="tel" className="input" placeholder="+1 555 000 0000" />
          </div>
          <div>
            <label className="label">Website</label>
            <input {...register("website")} type="url" className="input" placeholder="https://company.com" />
            {errors.website && (
              <p className="mt-1 text-xs text-red-400">{errors.website.message}</p>
            )}
          </div>
        </div>

        <div>
          <label className="label">Address</label>
          <textarea {...register("address")} className="input min-h-[80px] resize-y" placeholder="123 Main St, City, Country" />
        </div>

        <div>
          <label className="label">VAT / Tax Number</label>
          <input {...register("vat_number")} className="input" placeholder="IT01234567890" />
        </div>

        <div>
          <label className="label">Legal Disclaimer</label>
          <textarea
            {...register("legal_disclaimer")}
            className="input min-h-[100px] resize-y text-xs"
            placeholder="This report is confidential and intended solely for the use of the individual or entity to whom it is addressed…"
          />
          <p className="mt-1 text-xs text-slate-500">
            This text appears in the footer of all generated reports.
          </p>
        </div>
      </div>

      <div className="card space-y-4">
        <h3 className="font-semibold text-slate-100">Report Branding Colors</h3>
        <p className="text-xs text-slate-500">
          These are the default colors for new projects. Each project can override them individually.
        </p>
        <div className="grid grid-cols-2 gap-6">
          <div>
            <label className="label">Primary color</label>
            <div className="flex items-center gap-3">
              <input
                {...register("primary_color")}
                type="color"
                className="h-10 w-16 rounded border border-slate-700 bg-slate-800 p-1 cursor-pointer"
              />
              <input
                {...register("primary_color")}
                className="input flex-1 font-mono text-xs"
                placeholder="#2563eb"
              />
            </div>
          </div>
          <div>
            <label className="label">Secondary color</label>
            <div className="flex items-center gap-3">
              <input
                {...register("secondary_color")}
                type="color"
                className="h-10 w-16 rounded border border-slate-700 bg-slate-800 p-1 cursor-pointer"
              />
              <input
                {...register("secondary_color")}
                className="input flex-1 font-mono text-xs"
                placeholder="#64748b"
              />
            </div>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={isSubmitting || (!isDirty && !logoFile)}
          className="btn-primary"
        >
          {isSubmitting ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Save className="h-4 w-4" />
          )}
          Save Organization Settings
        </button>
        {(isDirty || logoFile) && (
          <span className="text-xs text-amber-400">You have unsaved changes</span>
        )}
      </div>
    </form>
  );
}

// ─── License Section ──────────────────────────────────────────────────────────

const LICENSE_KEY_RE = /^RS-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/i;

const licenseSchema = z.object({
  license_key: z
    .string()
    .min(1, "License key is required")
    .transform((v) => v.trim().toUpperCase())
    .refine((v) => LICENSE_KEY_RE.test(v), {
      message: "Invalid format — expected RS-XXXX-XXXX-XXXX-XXXX",
    }),
});

type LicenseFormData = z.infer<typeof licenseSchema>;

const STATUS_CONFIG: Record<
  LicenseStatusCode,
  { label: string; icon: React.ReactNode; color: string }
> = {
  trial_active: {
    label: "Trial Active",
    icon: <Clock className="h-5 w-5" />,
    color: "text-green-400",
  },
  trial_expired: {
    label: "Trial Expired",
    icon: <AlertCircle className="h-5 w-5" />,
    color: "text-red-400",
  },
  pro_active: {
    label: "PRO Active",
    icon: <CheckCircle2 className="h-5 w-5" />,
    color: "text-blue-400",
  },
  pro_expired: {
    label: "PRO Expired",
    icon: <AlertCircle className="h-5 w-5" />,
    color: "text-red-400",
  },
  invalid: {
    label: "Invalid",
    icon: <AlertCircle className="h-5 w-5" />,
    color: "text-red-400",
  },
};

function LicenseSection() {
  const { data: license, isLoading } = useLicenseStatus();
  const activate = useActivateLicense();

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    reset,
    setError,
  } = useForm<LicenseFormData>({
    resolver: zodResolver(licenseSchema),
  });

  async function onActivate(data: LicenseFormData) {
    try {
      await activate.mutateAsync({ license_key: data.license_key });
      toast.success("License activated successfully!");
      reset();
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error?: string; detail?: string } } };
      const msg =
        axiosErr.response?.data?.error ??
        axiosErr.response?.data?.detail ??
        "Failed to activate license.";
      setError("license_key", { message: msg });
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8 text-slate-500">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        Loading license…
      </div>
    );
  }

  const cfg = license ? STATUS_CONFIG[license.status] : null;

  return (
    <div className="space-y-4">
      {/* Current status */}
      {license && cfg && (
        <div className="card">
          <h3 className="font-semibold text-slate-100 mb-4 flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Current License
          </h3>
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span className={cfg.color}>{cfg.icon}</span>
              <span className={`font-semibold ${cfg.color}`}>{cfg.label}</span>
            </div>
            {license.license_key && (
              <div className="flex items-center gap-2">
                <Key className="h-4 w-4 text-slate-500" />
                <code className="text-xs text-slate-400 font-mono">{license.license_key}</code>
              </div>
            )}
            {license.trial_expires_at && (
              <p className="text-sm text-slate-400">
                Trial period:{" "}
                <span className="text-slate-200">
                  {format(new Date(license.trial_expires_at), "MMMM d, yyyy")}
                </span>
              </p>
            )}
            {license.days_remaining !== null && license.status === "trial_active" && (
              <p className="text-sm text-slate-400">
                Days remaining:{" "}
                <span className={`font-semibold ${license.days_remaining < 7 ? "text-amber-400" : "text-slate-200"}`}>
                  {license.days_remaining}
                </span>
              </p>
            )}

            <div className="mt-4 space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <span className={license.is_active ? "text-green-400" : "text-slate-600"}>
                  {license.is_active ? "✓" : "✗"}
                </span>
                <span className={license.is_active ? "text-slate-300" : "text-slate-600"}>
                  Create projects
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className={license.is_active ? "text-green-400" : "text-slate-600"}>
                  {license.is_active ? "✓" : "✗"}
                </span>
                <span className={license.is_active ? "text-slate-300" : "text-slate-600"}>
                  Export reports
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className={license.is_active ? "text-green-400" : "text-slate-600"}>
                  {license.is_active ? "✓" : "✗"}
                </span>
                <span className={license.is_active ? "text-slate-300" : "text-slate-600"}>
                  Import scanner output
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Activate form */}
      <div className="card">
        <h3 className="font-semibold text-slate-100 mb-2 flex items-center gap-2">
          <Key className="h-4 w-4" />
          Activate PRO License
        </h3>
        <p className="text-sm text-slate-500 mb-4">
          Enter your license key to activate PRO features. To purchase a license or for
          custom requirements contact{" "}
          <a
            href="mailto:sales@dognet-technologies.online"
            className="text-blue-400 hover:text-blue-300"
          >
            sales@dognet-technologies.online
          </a>
          .
        </p>
        <form onSubmit={handleSubmit(onActivate)} className="flex gap-3">
          <div className="flex-1">
            <input
              {...register("license_key")}
              className="input font-mono"
              placeholder="RS-XXXX-XXXX-XXXX-XXXX"
            />
            {errors.license_key && (
              <p className="mt-1 text-xs text-red-400">{errors.license_key.message}</p>
            )}
          </div>
          <button type="submit" disabled={isSubmitting} className="btn-primary shrink-0">
            {isSubmitting ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              "Activate"
            )}
          </button>
        </form>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

type SettingsTab = "profile" | "organization" | "license";

export default function SettingsPage() {
  const [tab, setTab] = useState<SettingsTab>("profile");

  const TABS: { key: SettingsTab; label: string; icon: React.ReactNode }[] = [
    { key: "profile", label: "Profile", icon: <User className="h-4 w-4" /> },
    { key: "organization", label: "Organization", icon: <Building2 className="h-4 w-4" /> },
    { key: "license", label: "License", icon: <Shield className="h-4 w-4" /> },
  ];

  return (
    <Layout>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-100">Settings</h1>
        <p className="text-slate-400 text-sm mt-1">
          Manage your profile, organization and license.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-slate-800 mb-6">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              tab === t.key
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {t.icon}
            {t.label}
          </button>
        ))}
      </div>

      <div className="max-w-2xl">
        {tab === "profile" && <ProfileSection />}
        {tab === "organization" && <OrganizationSection />}
        {tab === "license" && <LicenseSection />}
      </div>
    </Layout>
  );
}

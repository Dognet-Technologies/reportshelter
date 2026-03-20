/**
 * Force-password-change page shown on first login when must_change_password=true.
 * Blocks access to the rest of the app until the password is changed.
 */
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, Loader2, Eye, EyeOff, KeyRound } from "lucide-react";
import { useState } from "react";
import toast from "react-hot-toast";
import { useChangePassword } from "@/api/hooks";
import { useAuthStore } from "@/store/authStore";
import { apiClient } from "@/api/client";
import type { User } from "@/api/types";

const schema = z
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

type FormData = z.infer<typeof schema>;

export default function ChangePasswordPage() {
  const navigate = useNavigate();
  const { setUser, logout } = useAuthStore();
  const changePassword = useChangePassword();
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError,
  } = useForm<FormData>({ resolver: zodResolver(schema) });

  async function onSubmit(data: FormData) {
    try {
      await changePassword.mutateAsync(data);
      // Re-fetch updated user (must_change_password now false)
      const res = await apiClient.get<User>("/auth/me/");
      setUser(res.data);
      toast.success("Password changed successfully. Welcome!");
      navigate("/dashboard");
    } catch (err: unknown) {
      const axiosErr = err as {
        response?: { data?: { errors?: Record<string, string[]>; error?: string } };
      };
      const fieldErrors = axiosErr.response?.data?.errors;
      if (fieldErrors) {
        Object.entries(fieldErrors).forEach(([field, messages]) => {
          setError(field as keyof FormData, { message: messages[0] });
        });
      } else {
        setError("root", {
          message: axiosErr.response?.data?.error ?? "Failed to change password.",
        });
      }
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 bg-slate-950">
      <div className="card w-full max-w-md">
        {/* Header */}
        <div className="flex flex-col items-center mb-6">
          <div className="flex items-center justify-center h-14 w-14 rounded-full bg-amber-500/10 mb-3">
            <KeyRound className="h-7 w-7 text-amber-400" />
          </div>
          <h1 className="text-xl font-bold text-slate-100">Password Change Required</h1>
          <p className="text-slate-400 text-sm mt-1 text-center">
            For security reasons, you must set a new password before continuing.
          </p>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} noValidate className="space-y-4">
          {errors.root && (
            <div className="rounded-md border border-red-700 bg-red-950 px-4 py-3 text-sm text-red-300">
              {errors.root.message}
            </div>
          )}

          {/* Current password */}
          <div>
            <label className="label">Current password</label>
            <div className="relative">
              <input
                {...register("current_password")}
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
            {errors.current_password && (
              <p className="mt-1 text-xs text-red-400">{errors.current_password.message}</p>
            )}
          </div>

          {/* New password */}
          <div>
            <label className="label">New password</label>
            <div className="relative">
              <input
                {...register("new_password")}
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
            {errors.new_password && (
              <p className="mt-1 text-xs text-red-400">{errors.new_password.message}</p>
            )}
            <p className="mt-1 text-xs text-slate-500">
              At least 12 characters, one uppercase letter, one number.
            </p>
          </div>

          {/* Confirm password */}
          <div>
            <label className="label">Confirm new password</label>
            <div className="relative">
              <input
                {...register("confirm_password")}
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
            {errors.confirm_password && (
              <p className="mt-1 text-xs text-red-400">{errors.confirm_password.message}</p>
            )}
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="btn-primary w-full mt-2"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Saving…
              </>
            ) : (
              <>
                <ShieldCheck className="h-4 w-4" />
                Set new password
              </>
            )}
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-slate-600">
          <button
            type="button"
            onClick={() => logout()}
            className="text-slate-500 hover:text-slate-300 underline"
          >
            Logout and return to login
          </button>
        </p>
      </div>
    </div>
  );
}

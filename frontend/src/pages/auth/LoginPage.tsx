/**
 * Login page with email/password form, Zod validation, and JWT auth.
 */
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Link, useNavigate } from "react-router-dom";
import { ShieldCheck, Loader2, Eye, EyeOff } from "lucide-react";
import { useState } from "react";
import toast from "react-hot-toast";
import { apiClient } from "@/api/client";
import { useAuthStore } from "@/store/authStore";

const loginSchema = z.object({
  email: z.string().email("Enter a valid email address"),
  password: z.string().min(1, "Password is required"),
});

type LoginFormData = z.infer<typeof loginSchema>;

interface LoginResponse {
  access: string;
  refresh: string;
  user: import("@/api/types").User;
  must_change_password: boolean;
}

/**
 * Logo shown above the login card.
 * Tries to load /logo.png from the public folder.
 * Falls back to the ShieldCheck icon if the file is missing.
 * To use your own logo: place logo.png in frontend/public/.
 */
function LoginLogo() {
  const [imgError, setImgError] = useState(false);
  if (!imgError) {
    return (
      <img
        src="/logo.png"
        alt="CyberReport Pro"
        className="h-16 w-auto mb-3 object-contain"
        onError={() => setImgError(true)}
      />
    );
  }
  return <ShieldCheck className="h-12 w-12 text-blue-500 mb-3" />;
}

export default function LoginPage() {
  const navigate = useNavigate();
  const { setTokens, setUser } = useAuthStore();
  const [showPassword, setShowPassword] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError,
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  });

  async function onSubmit(data: LoginFormData) {
    try {
      const res = await apiClient.post<LoginResponse>("/auth/login/", data);
      setTokens(res.data.access, res.data.refresh);
      setUser(res.data.user);
      if (res.data.must_change_password) {
        navigate("/change-password");
      } else {
        toast.success("Welcome back!");
        navigate("/dashboard");
      }
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string; error?: string; non_field_errors?: string[] } } };
      const detail =
        axiosErr.response?.data?.error ??
        axiosErr.response?.data?.detail ??
        axiosErr.response?.data?.non_field_errors?.[0] ??
        "Invalid credentials";
      setError("root", { message: detail });
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 bg-slate-950">
      <div className="card w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <LoginLogo />
          <h1 className="text-2xl font-bold text-slate-100">CyberReport Pro</h1>
          <p className="text-slate-400 text-sm mt-1">Sign in to your account</p>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} noValidate className="space-y-4">
          {/* Root error */}
          {errors.root && (
            <div className="rounded-md border border-red-700 bg-red-950 px-4 py-3 text-sm text-red-300">
              {errors.root.message}
            </div>
          )}

          {/* Email */}
          <div>
            <label htmlFor="email" className="label">
              Email address
            </label>
            <input
              {...register("email")}
              id="email"
              type="email"
              autoComplete="email"
              className="input"
              placeholder="you@company.com"
            />
            {errors.email && (
              <p className="mt-1 text-xs text-red-400">{errors.email.message}</p>
            )}
          </div>

          {/* Password */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label htmlFor="password" className="label mb-0">
                Password
              </label>
              <Link
                to="/forgot-password"
                className="text-xs text-blue-400 hover:text-blue-300"
              >
                Forgot password?
              </Link>
            </div>
            <div className="relative">
              <input
                {...register("password")}
                id="password"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                className="input pr-10"
                placeholder="••••••••"
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            {errors.password && (
              <p className="mt-1 text-xs text-red-400">{errors.password.message}</p>
            )}
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={isSubmitting}
            className="btn-primary w-full mt-2"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Signing in…
              </>
            ) : (
              "Sign in"
            )}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-slate-500">
          Don&apos;t have an account?{" "}
          <Link to="/register" className="text-blue-400 hover:text-blue-300 font-medium">
            Create one
          </Link>
        </p>
      </div>
    </div>
  );
}

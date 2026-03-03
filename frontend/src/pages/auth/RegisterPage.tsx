/**
 * Registration page: organization name, name, email, password with confirmation.
 */
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Link, useNavigate } from "react-router-dom";
import { ShieldCheck, Loader2, Eye, EyeOff } from "lucide-react";
import { useState } from "react";
import toast from "react-hot-toast";
import { apiClient } from "@/api/client";

const registerSchema = z
  .object({
    organization_name: z.string().min(2, "Organization name must be at least 2 characters"),
    first_name: z.string().min(1, "First name is required"),
    last_name: z.string().min(1, "Last name is required"),
    email: z.string().email("Enter a valid email address"),
    password: z
      .string()
      .min(8, "Password must be at least 8 characters")
      .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
      .regex(/[0-9]/, "Password must contain at least one number"),
    confirm_password: z.string().min(1, "Please confirm your password"),
  })
  .refine((d) => d.password === d.confirm_password, {
    message: "Passwords do not match",
    path: ["confirm_password"],
  });

type RegisterFormData = z.infer<typeof registerSchema>;

export default function RegisterPage() {
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError,
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
  });

  async function onSubmit(data: RegisterFormData) {
    try {
      await apiClient.post("/auth/register/", {
        organization_name: data.organization_name,
        first_name: data.first_name,
        last_name: data.last_name,
        email: data.email,
        password: data.password,
      });
      toast.success(
        "Account created! Please check your email to verify your account.",
        { duration: 6000 }
      );
      navigate("/login");
    } catch (err: unknown) {
      const axiosErr = err as {
        response?: { data?: Record<string, string | string[]> };
      };
      const data_err = axiosErr.response?.data;
      if (data_err) {
        // Map field errors back to the form
        for (const [key, messages] of Object.entries(data_err)) {
          const msg = Array.isArray(messages) ? messages[0] : messages;
          if (key === "email" || key === "password" || key === "first_name" || key === "last_name") {
            setError(key, { message: msg });
          } else {
            setError("root", { message: msg });
          }
        }
      } else {
        setError("root", { message: "Registration failed. Please try again." });
      }
    }
  }

  function Field({
    id,
    label,
    type = "text",
    placeholder,
    error,
    ...props
  }: React.InputHTMLAttributes<HTMLInputElement> & {
    id: string;
    label: string;
    error?: string;
  }) {
    return (
      <div>
        <label htmlFor={id} className="label">
          {label}
        </label>
        <input
          {...props}
          id={id}
          type={type}
          placeholder={placeholder}
          className="input"
        />
        {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-8 bg-slate-950">
      <div className="card w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <ShieldCheck className="h-12 w-12 text-blue-500 mb-3" />
          <h1 className="text-2xl font-bold text-slate-100">Create Account</h1>
          <p className="text-slate-400 text-sm mt-1">
            Start your 30-day free trial
          </p>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} noValidate className="space-y-4">
          {errors.root && (
            <div className="rounded-md border border-red-700 bg-red-950 px-4 py-3 text-sm text-red-300">
              {errors.root.message}
            </div>
          )}

          <Field
            {...register("organization_name")}
            id="organization_name"
            label="Organization name"
            placeholder="Acme Security Ltd."
            error={errors.organization_name?.message}
          />

          <div className="grid grid-cols-2 gap-3">
            <Field
              {...register("first_name")}
              id="first_name"
              label="First name"
              placeholder="Alice"
              autoComplete="given-name"
              error={errors.first_name?.message}
            />
            <Field
              {...register("last_name")}
              id="last_name"
              label="Last name"
              placeholder="Smith"
              autoComplete="family-name"
              error={errors.last_name?.message}
            />
          </div>

          <Field
            {...register("email")}
            id="email"
            label="Email address"
            type="email"
            placeholder="alice@company.com"
            autoComplete="email"
            error={errors.email?.message}
          />

          {/* Password */}
          <div>
            <label htmlFor="password" className="label">
              Password
            </label>
            <div className="relative">
              <input
                {...register("password")}
                id="password"
                type={showPassword ? "text" : "password"}
                autoComplete="new-password"
                className="input pr-10"
                placeholder="Min 8 chars, 1 uppercase, 1 number"
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

          {/* Confirm Password */}
          <div>
            <label htmlFor="confirm_password" className="label">
              Confirm password
            </label>
            <div className="relative">
              <input
                {...register("confirm_password")}
                id="confirm_password"
                type={showConfirm ? "text" : "password"}
                autoComplete="new-password"
                className="input pr-10"
                placeholder="••••••••"
              />
              <button
                type="button"
                onClick={() => setShowConfirm((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                aria-label={showConfirm ? "Hide password" : "Show password"}
              >
                {showConfirm ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            {errors.confirm_password && (
              <p className="mt-1 text-xs text-red-400">
                {errors.confirm_password.message}
              </p>
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
                Creating account…
              </>
            ) : (
              "Create account"
            )}
          </button>

          <p className="text-xs text-slate-500 text-center">
            By creating an account you agree to our terms of service and privacy policy.
          </p>
        </form>

        <p className="mt-6 text-center text-sm text-slate-500">
          Already have an account?{" "}
          <Link to="/login" className="text-blue-400 hover:text-blue-300 font-medium">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}

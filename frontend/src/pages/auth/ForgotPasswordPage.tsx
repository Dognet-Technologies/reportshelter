import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Link } from "react-router-dom";
import { ShieldCheck, Loader2, ArrowLeft, MailCheck } from "lucide-react";
import { useState } from "react";
import iconUrl from "@/components/Icon.png";
import { apiClient } from "@/api/client";

const schema = z.object({
  email: z.string().email("Enter a valid email address"),
});

type FormData = z.infer<typeof schema>;

function LoginLogo() {
  const [imgError, setImgError] = useState(false);
  if (!imgError) {
    return (
      <img
        src={iconUrl}
        alt="ReportShelter PRO"
        className="h-16 w-auto mb-3 object-contain"
        onError={() => setImgError(true)}
      />
    );
  }
  return <ShieldCheck className="h-12 w-12 text-blue-500 mb-3" />;
}

export default function ForgotPasswordPage() {
  const [sent, setSent] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError,
  } = useForm<FormData>({ resolver: zodResolver(schema) });

  async function onSubmit(data: FormData) {
    try {
      await apiClient.post("/auth/password/reset/", { email: data.email });
      setSent(true);
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error?: string }; status?: number } };
      const msg =
        axiosErr.response?.data?.error ??
        "Something went wrong. Please try again.";
      setError("root", { message: msg });
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 bg-slate-950">
      <div className="card w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <LoginLogo />
          <h1 className="text-2xl font-bold text-slate-100">Forgot password?</h1>
          <p className="text-slate-400 text-sm mt-1 text-center">
            Enter your email and we'll send you instructions
          </p>
        </div>

        {sent ? (
          <div className="flex flex-col items-center gap-4 py-4">
            <MailCheck className="h-12 w-12 text-green-400" />
            <p className="text-slate-200 text-center font-medium">Check your inbox</p>
            <p className="text-slate-400 text-sm text-center">
              If that email is registered, you'll receive a temporary password and an
              activation link. Click the link to activate the reset, then log in.
            </p>
            <Link to="/login" className="btn-primary mt-2 w-full text-center">
              Back to login
            </Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit(onSubmit)} noValidate className="space-y-4">
            {errors.root && (
              <div className="rounded-md border border-red-700 bg-red-950 px-4 py-3 text-sm text-red-300">
                {errors.root.message}
              </div>
            )}

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

            <button
              type="submit"
              disabled={isSubmitting}
              className="btn-primary w-full mt-2"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Sending…
                </>
              ) : (
                "Send reset instructions"
              )}
            </button>

            <Link
              to="/login"
              className="flex items-center justify-center gap-1.5 mt-2 text-sm text-slate-400 hover:text-slate-200"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              Back to login
            </Link>
          </form>
        )}
      </div>
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ShieldCheck, Loader2, CheckCircle, XCircle } from "lucide-react";
import iconUrl from "@/components/Icon.png";
import { apiClient } from "@/api/client";

type State = "loading" | "success" | "error";

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

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const [state, setState] = useState<State>("loading");
  const [errorMsg, setErrorMsg] = useState("");
  const calledRef = useRef(false);

  useEffect(() => {
    if (calledRef.current) return;
    calledRef.current = true;

    const token = searchParams.get("token");
    if (!token) {
      setErrorMsg("No reset token found in the link.");
      setState("error");
      return;
    }

    apiClient
      .post("/auth/password/reset/confirm/", { token })
      .then(() => setState("success"))
      .catch((err: unknown) => {
        const axiosErr = err as { response?: { data?: { error?: string } } };
        setErrorMsg(axiosErr.response?.data?.error ?? "This link is invalid or has expired.");
        setState("error");
      });
  }, [searchParams]);

  return (
    <div className="flex min-h-screen items-center justify-center px-4 bg-slate-950">
      <div className="card w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <LoginLogo />
          <h1 className="text-2xl font-bold text-slate-100">Password reset</h1>
        </div>

        <div className="flex flex-col items-center gap-4 py-4 text-center">
          {state === "loading" && (
            <>
              <Loader2 className="h-10 w-10 text-blue-400 animate-spin" />
              <p className="text-slate-400 text-sm">Activating your reset link…</p>
            </>
          )}

          {state === "success" && (
            <>
              <CheckCircle className="h-12 w-12 text-green-400" />
              <p className="text-slate-200 font-medium">Reset activated</p>
              <p className="text-slate-400 text-sm">
                Your password has been changed to the temporary one in your email.
                Log in and you'll be asked to set a new permanent password.
              </p>
              <Link to="/login" className="btn-primary mt-2 w-full">
                Go to login
              </Link>
            </>
          )}

          {state === "error" && (
            <>
              <XCircle className="h-12 w-12 text-red-400" />
              <p className="text-slate-200 font-medium">Link not valid</p>
              <p className="text-slate-400 text-sm">{errorMsg}</p>
              <Link to="/forgot-password" className="btn-primary mt-2 w-full">
                Request a new link
              </Link>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

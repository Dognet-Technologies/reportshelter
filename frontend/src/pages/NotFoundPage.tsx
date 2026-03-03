import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4">
      <h1 className="text-6xl font-bold text-slate-600">404</h1>
      <p className="text-slate-400">Page not found.</p>
      <Link to="/dashboard" className="btn-primary">
        Go to Dashboard
      </Link>
    </div>
  );
}

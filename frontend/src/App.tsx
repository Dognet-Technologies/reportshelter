import { Routes, Route, Navigate } from "react-router-dom";
import { useAuthStore } from "@/store/authStore";

// Auth pages
import LoginPage from "@/pages/auth/LoginPage";
import RegisterPage from "@/pages/auth/RegisterPage";
import ChangePasswordPage from "@/pages/auth/ChangePasswordPage";
import ForgotPasswordPage from "@/pages/auth/ForgotPasswordPage";
import ResetPasswordPage from "@/pages/auth/ResetPasswordPage";

// App pages
import DashboardPage from "@/pages/DashboardPage";
import NotFoundPage from "@/pages/NotFoundPage";
import ProjectListPage from "@/pages/projects/ProjectListPage";
import ProjectDetailPage from "@/pages/projects/ProjectDetailPage";
import SubProjectPage from "@/pages/projects/SubProjectPage";
import VulnerabilityDetailPage from "@/pages/vulnerabilities/VulnerabilityDetailPage";
import ReportBuilderPage from "@/pages/reports/ReportBuilderPage";
import SettingsPage from "@/pages/settings/SettingsPage";

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const user = useAuthStore((s) => s.user);
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (user?.must_change_password) return <Navigate to="/change-password" replace />;
  return <>{children}</>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  return !isAuthenticated ? <>{children}</> : <Navigate to="/dashboard" replace />;
}

export default function App() {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/login" element={<PublicRoute><LoginPage /></PublicRoute>} />
      <Route path="/register" element={<PublicRoute><RegisterPage /></PublicRoute>} />
      <Route path="/forgot-password" element={<PublicRoute><ForgotPasswordPage /></PublicRoute>} />
      <Route path="/reset-password" element={<PublicRoute><ResetPasswordPage /></PublicRoute>} />

      {/* Force password change (authenticated but restricted) */}
      <Route path="/change-password" element={<ChangePasswordPage />} />

      {/* Private routes */}
      <Route
        path="/dashboard"
        element={<PrivateRoute><DashboardPage /></PrivateRoute>}
      />
      <Route
        path="/projects"
        element={<PrivateRoute><ProjectListPage /></PrivateRoute>}
      />
      <Route
        path="/projects/:id"
        element={<PrivateRoute><ProjectDetailPage /></PrivateRoute>}
      />
      <Route
        path="/projects/:projectId/subprojects/:id"
        element={<PrivateRoute><SubProjectPage /></PrivateRoute>}
      />
      <Route
        path="/vulnerabilities/:id"
        element={<PrivateRoute><VulnerabilityDetailPage /></PrivateRoute>}
      />
      <Route
        path="/projects/:projectId/reports/builder/:subprojectId"
        element={<PrivateRoute><ReportBuilderPage /></PrivateRoute>}
      />
      {/* Legacy URL: keep working via redirect-like catch */}
      <Route
        path="/reports/builder/:subprojectId"
        element={<PrivateRoute><ReportBuilderPage /></PrivateRoute>}
      />
      <Route
        path="/settings"
        element={<PrivateRoute><SettingsPage /></PrivateRoute>}
      />

      {/* Redirects */}
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}

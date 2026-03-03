import { Routes, Route, Navigate } from "react-router-dom";
import { useAuthStore } from "@/store/authStore";

// Auth pages
import LoginPage from "@/pages/auth/LoginPage";
import RegisterPage from "@/pages/auth/RegisterPage";

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
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
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

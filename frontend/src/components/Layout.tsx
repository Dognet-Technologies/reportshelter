/**
 * Main application layout with sidebar navigation and license banner.
 */
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  FolderOpen,
  Settings,
  LogOut,
  ShieldCheck,
  Menu,
  X,
} from "lucide-react";
import { useState } from "react";
import { useAuthStore } from "@/store/authStore";
import { apiClient } from "@/api/client";
import { LicenseBanner } from "./LicenseBanner";
import toast from "react-hot-toast";

interface NavItem {
  label: string;
  to: string;
  icon: React.ReactNode;
}

const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", to: "/dashboard", icon: <LayoutDashboard className="h-4 w-4" /> },
  { label: "Projects", to: "/projects", icon: <FolderOpen className="h-4 w-4" /> },
  { label: "Settings", to: "/settings", icon: <Settings className="h-4 w-4" /> },
];

interface LayoutProps {
  children: React.ReactNode;
}

export function Layout({ children }: LayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout, refreshToken } = useAuthStore();
  const [mobileOpen, setMobileOpen] = useState(false);

  async function handleLogout() {
    try {
      await apiClient.post("/auth/logout/", { refresh: refreshToken });
    } catch {
      // Ignore errors during logout
    }
    logout();
    navigate("/login");
    toast.success("Logged out successfully");
  }

  function isActive(to: string) {
    return location.pathname === to || location.pathname.startsWith(to + "/");
  }

  const NavLinks = () => (
    <nav className="flex flex-col gap-1">
      {NAV_ITEMS.map((item) => (
        <Link
          key={item.to}
          to={item.to}
          onClick={() => setMobileOpen(false)}
          className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
            isActive(item.to)
              ? "bg-blue-600 text-white"
              : "text-slate-400 hover:bg-slate-800 hover:text-slate-100"
          }`}
        >
          {item.icon}
          {item.label}
        </Link>
      ))}
    </nav>
  );

  return (
    <div className="flex h-screen overflow-hidden bg-slate-950">
      {/* Sidebar — desktop */}
      <aside className="hidden lg:flex w-60 flex-col border-r border-slate-800 bg-slate-900">
        <div className="flex h-16 items-center gap-2 border-b border-slate-800 px-4">
          <ShieldCheck className="h-6 w-6 text-blue-500" />
          <span className="font-bold text-slate-100">ReportShelter PRO</span>
        </div>
        <div className="flex flex-1 flex-col gap-4 p-4 overflow-y-auto">
          <NavLinks />
        </div>
        <div className="border-t border-slate-800 p-4">
          <div className="mb-2 text-xs text-slate-500 truncate">
            {user?.email}
          </div>
          <button
            onClick={handleLogout}
            className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-colors"
          >
            <LogOut className="h-4 w-4" />
            Log out
          </button>
        </div>
      </aside>

      {/* Mobile sidebar overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div
            className="absolute inset-0 bg-black/60"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="absolute left-0 top-0 h-full w-60 flex flex-col border-r border-slate-800 bg-slate-900 z-50">
            <div className="flex h-16 items-center justify-between border-b border-slate-800 px-4">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-6 w-6 text-blue-500" />
                <span className="font-bold text-slate-100">ReportShelter PRO</span>
              </div>
              <button
                onClick={() => setMobileOpen(false)}
                className="text-slate-400 hover:text-slate-100"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="flex flex-1 flex-col gap-4 p-4">
              <NavLinks />
            </div>
            <div className="border-t border-slate-800 p-4">
              <div className="mb-2 text-xs text-slate-500 truncate">
                {user?.email}
              </div>
              <button
                onClick={handleLogout}
                className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-colors"
              >
                <LogOut className="h-4 w-4" />
                Log out
              </button>
            </div>
          </aside>
        </div>
      )}

      {/* Main content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Mobile header */}
        <header className="flex h-16 items-center border-b border-slate-800 px-4 lg:hidden">
          <button
            onClick={() => setMobileOpen(true)}
            className="text-slate-400 hover:text-slate-100"
          >
            <Menu className="h-5 w-5" />
          </button>
          <div className="ml-3 flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-blue-500" />
            <span className="font-bold text-sm text-slate-100">ReportShelter PRO</span>
          </div>
        </header>

        {/* License banner */}
        <LicenseBanner />

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto max-w-screen-2xl px-4 py-6 sm:px-5 lg:px-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}

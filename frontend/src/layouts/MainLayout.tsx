import { useState } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  BarChart3,
  History,
  Home,
  LogOut,
  Menu,
  Moon,
  ScanSearch,
  Settings,
  ShieldCheck,
  Sun,
  User,
  X,
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { useTheme } from "@/context/ThemeContext";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function MainLayout() {
  const { isAuthenticated, user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [mobileOpen, setMobileOpen] = useState(false);
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    setMobileOpen(false);
    navigate("/");
  };

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    cn(
      "px-3 py-1.5 rounded-lg text-sm font-medium transition-colors flex items-center gap-1.5",
      isActive
        ? "text-secondary font-semibold"
        : "text-muted hover:text-foreground hover:bg-surface-elevated",
    );

  const dockLinkClass = ({ isActive }: { isActive: boolean }) =>
    cn(
      "flex flex-col items-center justify-center gap-0.5 px-4 py-1.5 text-[11px] font-medium transition-colors border-t-2",
      isActive
        ? "border-secondary text-secondary font-semibold"
        : "border-transparent text-muted hover:text-foreground",
    );

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground pb-16">
      {/* Crisp Top Navigation Header */}
      <header className="sticky top-0 z-40 border-b border-border bg-surface/95 backdrop-blur">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-4">
          <div className="flex items-center gap-6">
            <Link to="/" className="flex items-center gap-2 shrink-0">
              <div className="h-7 w-7 rounded-md bg-blue-50 dark:bg-secondary/15 border border-blue-200 dark:border-secondary/30 flex items-center justify-center">
                <ShieldCheck className="h-4 w-4 text-secondary" />
              </div>
              <span className="font-bold tracking-tight text-sm sm:text-base text-foreground">
                LINK VERIFY <span className="text-secondary">AI</span>
              </span>
            </Link>

            <nav className="hidden md:flex items-center gap-1" aria-label="Primary Navigation">
              <NavLink to="/scanner" className={navLinkClass}>
                URL Scanner
              </NavLink>
              <NavLink to="/dashboard" className={navLinkClass}>
                <BarChart3 className="h-3.5 w-3.5" />
                Dashboard &amp; Analytics
              </NavLink>
              <NavLink to="/history" className={navLinkClass}>
                Scan History
              </NavLink>
              <NavLink to="/about" className={navLinkClass}>
                Methodology
              </NavLink>
            </nav>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="icon"
              onClick={toggleTheme}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              className="h-8 w-8"
            >
              {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </Button>

            <div className="hidden md:flex items-center gap-2">
              {isAuthenticated ? (
                <div className="flex items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 py-1">
                  <Link to="/profile" className="flex items-center gap-2 text-xs font-medium text-foreground hover:text-secondary">
                    <User className="h-3.5 w-3.5 text-muted" />
                    <span>{user?.display_name || user?.email}</span>
                  </Link>
                  <Badge variant="low" className="text-[10px] px-1.5 py-0">
                    Verified
                  </Badge>
                  <button
                    type="button"
                    onClick={handleLogout}
                    aria-label="Sign out"
                    title="Sign out"
                    className="ml-1 text-muted hover:text-foreground"
                  >
                    <LogOut className="h-3.5 w-3.5" />
                  </button>
                </div>
              ) : (
                <>
                  <Button variant="ghost" size="sm" asChild>
                    <Link to="/auth">Sign in</Link>
                  </Button>
                  <Button size="sm" asChild>
                    <Link to="/auth?tab=register">Get Started</Link>
                  </Button>
                </>
              )}
            </div>

            <Button
              variant="ghost"
              size="icon"
              className="md:hidden h-8 w-8"
              onClick={() => setMobileOpen((v) => !v)}
              aria-label="Toggle navigation menu"
            >
              {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </Button>
          </div>
        </div>

        {mobileOpen && (
          <div className="md:hidden border-t border-border bg-surface px-4 py-3 space-y-1">
            <NavLink to="/" end className={navLinkClass} onClick={() => setMobileOpen(false)}>
              Home
            </NavLink>
            <NavLink to="/scanner" className={navLinkClass} onClick={() => setMobileOpen(false)}>
              URL Scanner
            </NavLink>
            <NavLink to="/dashboard" className={navLinkClass} onClick={() => setMobileOpen(false)}>
              Dashboard &amp; Analytics
            </NavLink>
            <NavLink to="/history" className={navLinkClass} onClick={() => setMobileOpen(false)}>
              Scan History
            </NavLink>
            <NavLink to="/about" className={navLinkClass} onClick={() => setMobileOpen(false)}>
              Methodology
            </NavLink>
            <div className="pt-2 border-t border-border flex items-center gap-2">
              {isAuthenticated ? (
                <Button variant="outline" size="sm" className="w-full" onClick={handleLogout}>
                  <LogOut className="h-4 w-4" />
                  Sign out
                </Button>
              ) : (
                <Button size="sm" className="w-full" asChild>
                  <Link to="/auth" onClick={() => setMobileOpen(false)}>
                    Sign in / Register
                  </Link>
                </Button>
              )}
            </div>
          </div>
        )}
      </header>

      <main className="flex-1">
        <Outlet />
      </main>

      <footer className="border-t border-border bg-surface mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 text-xs text-muted">
          <div className="space-y-0.5">
            <p className="font-semibold text-foreground">LINK VERIFY AI — A Smarter First Check Before You Click.</p>
            <p>
              Static URL inspection, ML phishing classification, and external threat intelligence. Submitted links are never executed.
            </p>
          </div>
          <div className="flex items-center gap-5 shrink-0">
            <Link to="/scanner" className="hover:text-foreground">
              Scanner
            </Link>
            <Link to="/about" className="hover:text-foreground">
              Methodology
            </Link>
            <Link to="/auth" className="hover:text-foreground">
              Account
            </Link>
          </div>
        </div>
      </footer>

      {/* Bottom Quick-Navigation Dock (matching reference UI) */}
      <nav
        aria-label="Quick Navigation Dock"
        className="fixed bottom-0 inset-x-0 z-40 border-t border-border bg-surface/95 backdrop-blur"
      >
        <div className="max-w-md mx-auto flex items-center justify-around">
          <NavLink to="/" end className={dockLinkClass}>
            <Home className="h-4 w-4" />
            <span>Home</span>
          </NavLink>
          <NavLink to="/scanner" className={dockLinkClass}>
            <ScanSearch className="h-4 w-4" />
            <span>Scanner</span>
          </NavLink>
          <NavLink to="/dashboard" className={dockLinkClass}>
            <BarChart3 className="h-4 w-4" />
            <span>Analytics</span>
          </NavLink>
          <NavLink to="/history" className={dockLinkClass}>
            <History className="h-4 w-4" />
            <span>History</span>
          </NavLink>
          <NavLink to={isAuthenticated ? "/profile" : "/auth"} className={dockLinkClass}>
            <Settings className="h-4 w-4" />
            <span>{isAuthenticated ? "Settings" : "Account"}</span>
          </NavLink>
        </div>
      </nav>
    </div>
  );
}

import { useState } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/context/ToastContext";

const loginSchema = z.object({
  email: z.string().email("Enter a valid email address."),
  password: z.string().min(1, "Password is required."),
});

const registerSchema = z.object({
  displayName: z.string().min(2, "Display name must be at least 2 characters.").max(80),
  email: z.string().email("Enter a valid email address."),
  password: z.string().min(8, "Password must be at least 8 characters."),
});

type LoginValues = z.infer<typeof loginSchema>;
type RegisterValues = z.infer<typeof registerSchema>;

export function AuthPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialTab = searchParams.get("tab") === "register" ? "register" : "login";
  const [tab, setTab] = useState<"login" | "register">(initialTab);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const { login, register: registerUser, authMode } = useAuth();
  const { notify } = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  const redirectTo = (location.state as { from?: string } | null)?.from || "/dashboard";

  const loginForm = useForm<LoginValues>({ resolver: zodResolver(loginSchema) });
  const regForm = useForm<RegisterValues>({ resolver: zodResolver(registerSchema) });

  const switchTab = (next: "login" | "register") => {
    setTab(next);
    setErrorMsg(null);
    setSearchParams(next === "register" ? { tab: "register" } : {});
  };

  const handleLogin = async (values: LoginValues) => {
    setBusy(true);
    setErrorMsg(null);
    try {
      await login(values.email, values.password);
      notify({ title: "Signed in", description: "Welcome back to LINK VERIFY AI.", variant: "success" });
      navigate(redirectTo, { replace: true });
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Authentication failed.");
    } finally {
      setBusy(false);
    }
  };

  const handleRegister = async (values: RegisterValues) => {
    setBusy(true);
    setErrorMsg(null);
    try {
      const res = await registerUser(values.email, values.password, values.displayName);
      if (res.needsEmailConfirmation) {
        notify({
          title: "Verify your email",
          description: "Check your inbox to confirm your Supabase account before signing in.",
          variant: "info",
        });
        switchTab("login");
        return;
      }
      notify({ title: "Account created", description: "Your security workspace is ready.", variant: "success" });
      navigate(redirectTo, { replace: true });
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Registration failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-md mx-auto px-4 py-14">
      <Card>
        <CardHeader className="text-center space-y-2">
          <div className="h-11 w-11 rounded-xl bg-blue-50 dark:bg-secondary/15 border border-blue-200 dark:border-secondary/30 flex items-center justify-center mx-auto">
            <ShieldCheck className="h-6 w-6 text-secondary" />
          </div>
          <CardTitle className="text-xl">
            {tab === "login" ? "Sign in to LINK VERIFY AI" : "Create Security Account"}
          </CardTitle>
          <CardDescription>
            Save scan history, access dashboard analytics, and manage threat reports.
          </CardDescription>
          <div className="pt-1">
            <Badge variant="outline">
              Auth Provider: {authMode === "supabase" ? "Supabase Auth" : "Local JWT Auth"}
            </Badge>
          </div>
        </CardHeader>

        <CardContent className="space-y-5">
          <div className="grid grid-cols-2 rounded-lg border border-border bg-surface-elevated p-1">
            <button
              type="button"
              onClick={() => switchTab("login")}
              className={`py-1.5 text-sm font-medium rounded-md transition-colors ${
                tab === "login" ? "bg-surface text-foreground shadow-sm" : "text-muted hover:text-foreground"
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => switchTab("register")}
              className={`py-1.5 text-sm font-medium rounded-md transition-colors ${
                tab === "register" ? "bg-surface text-foreground shadow-sm" : "text-muted hover:text-foreground"
              }`}
            >
              Register
            </button>
          </div>

          {errorMsg && (
            <div
              className="rounded-lg border border-red-200 bg-red-50 text-red-700 dark:border-red-500/30 dark:bg-red-500/10 p-3 text-xs dark:text-red-400"
              role="alert"
            >
              {errorMsg}
            </div>
          )}

          {tab === "login" ? (
            <form onSubmit={loginForm.handleSubmit(handleLogin)} className="space-y-4" noValidate>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted" htmlFor="login-email">
                  Email
                </label>
                <Input id="login-email" type="email" {...loginForm.register("email")} />
                {loginForm.formState.errors.email && (
                  <p className="text-xs text-red-400">{loginForm.formState.errors.email.message}</p>
                )}
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-muted" htmlFor="login-password">
                    Password
                  </label>
                  <Link to="/reset-password" className="text-xs text-secondary hover:underline">
                    Forgot password?
                  </Link>
                </div>
                <Input id="login-password" type="password" {...loginForm.register("password")} />
                {loginForm.formState.errors.password && (
                  <p className="text-xs text-red-400">{loginForm.formState.errors.password.message}</p>
                )}
              </div>

              <Button type="submit" className="w-full" disabled={busy}>
                {busy ? "Signing in..." : "Sign In"}
              </Button>
            </form>
          ) : (
            <form onSubmit={regForm.handleSubmit(handleRegister)} className="space-y-4" noValidate>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted" htmlFor="reg-name">
                  Display Name
                </label>
                <Input id="reg-name" type="text" placeholder="Alex Rivera" {...regForm.register("displayName")} />
                {regForm.formState.errors.displayName && (
                  <p className="text-xs text-red-400">{regForm.formState.errors.displayName.message}</p>
                )}
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted" htmlFor="reg-email">
                  Email
                </label>
                <Input id="reg-email" type="email" placeholder="alex@company.com" {...regForm.register("email")} />
                {regForm.formState.errors.email && (
                  <p className="text-xs text-red-400">{regForm.formState.errors.email.message}</p>
                )}
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted" htmlFor="reg-password">
                  Password (min 8 chars)
                </label>
                <Input id="reg-password" type="password" {...regForm.register("password")} />
                {regForm.formState.errors.password && (
                  <p className="text-xs text-red-400">{regForm.formState.errors.password.message}</p>
                )}
              </div>

              <Button type="submit" className="w-full" disabled={busy}>
                {busy ? "Creating account..." : "Create Account"}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}


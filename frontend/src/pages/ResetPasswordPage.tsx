import { useState } from "react";
import { Link } from "react-router-dom";
import { KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/context/ToastContext";

export function ResetPasswordPage() {
  const { sendPasswordReset, authMode } = useAuth();
  const { notify } = useToast();
  const [email, setEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setStatusMsg(null);
    if (!email.trim()) {
      setErrorMsg("Please enter your account email.");
      return;
    }
    if (authMode === "local_jwt" && newPassword && newPassword.length < 8) {
      setErrorMsg("New password must be at least 8 characters.");
      return;
    }

    setBusy(true);
    try {
      const msg = await sendPasswordReset(email.trim(), newPassword || undefined);
      setStatusMsg(msg);
      notify({ title: "Password reset", description: msg, variant: "success" });
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to reset password.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-md mx-auto px-4 py-14">
      <Card>
        <CardHeader className="text-center space-y-2">
          <KeyRound className="h-8 w-8 text-primary mx-auto" />
          <CardTitle>Reset Password</CardTitle>
          <CardDescription>
            {authMode === "supabase"
              ? "Enter your email to receive a Supabase password recovery link."
              : "Local JWT development mode: enter your email and a new password."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {errorMsg && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400">
                {errorMsg}
              </div>
            )}
            {statusMsg && (
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-400">
                {statusMsg}
              </div>
            )}

            <div className="space-y-1.5">
              <label htmlFor="reset-email" className="text-xs font-medium text-muted">
                Email
              </label>
              <Input
                id="reset-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>

            {authMode === "local_jwt" && (
              <div className="space-y-1.5">
                <label htmlFor="reset-new-pw" className="text-xs font-medium text-muted">
                  New Password (min 8 characters)
                </label>
                <Input
                  id="reset-new-pw"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                />
              </div>
            )}

            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Processing..." : "Reset Password"}
            </Button>

            <div className="text-center">
              <Link to="/auth" className="text-xs text-primary hover:underline">
                Back to Sign In
              </Link>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}


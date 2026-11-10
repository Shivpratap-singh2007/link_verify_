import { useState } from "react";
import { User } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/context/ToastContext";
import { formatTimestamp } from "@/lib/utils";

export function ProfilePage() {
  const { user, updateDisplayName, logout } = useAuth();
  const { notify } = useToast();
  const [displayName, setDisplayName] = useState(user?.display_name ?? "");
  const [saving, setSaving] = useState(false);

  if (!user) return null;

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!displayName.trim()) return;
    setSaving(true);
    try {
      await updateDisplayName(displayName.trim());
      notify({ title: "Profile updated", description: "Display name saved.", variant: "success" });
    } catch (err) {
      notify({
        title: "Update failed",
        description: err instanceof Error ? err.message : "Could not update profile.",
        variant: "error",
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto px-4 sm:px-6 py-10 space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <User className="h-6 w-6 text-primary" />
          Account Profile
        </h1>
        <p className="text-sm text-muted">Manage your analyst identity and session.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Profile Information</CardTitle>
          <CardDescription>All scan history records are strictly scoped to your user UUID.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
            <div className="rounded-lg border border-border bg-background/50 p-3">
              <p className="text-xs text-muted">Email</p>
              <p className="font-medium mt-0.5">{user.email}</p>
            </div>
            <div className="rounded-lg border border-border bg-background/50 p-3">
              <p className="text-xs text-muted">Auth Provider</p>
              <div className="mt-1">
                <Badge variant="default">{user.auth_provider}</Badge>
              </div>
            </div>
            <div className="rounded-lg border border-border bg-background/50 p-3 sm:col-span-2">
              <p className="text-xs text-muted">Member Since</p>
              <p className="font-medium mt-0.5">{formatTimestamp(user.created_at)}</p>
            </div>
          </div>

          <form onSubmit={handleSave} className="space-y-3 pt-2 border-t border-border">
            <label htmlFor="profile-display-name" className="text-xs font-medium text-muted">
              Display Name
            </label>
            <div className="flex gap-2.5">
              <Input
                id="profile-display-name"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                required
                maxLength={80}
              />
              <Button type="submit" disabled={saving}>
                {saving ? "Saving..." : "Save"}
              </Button>
            </div>
          </form>

          <div className="pt-3 border-t border-border flex justify-end">
            <Button variant="destructive" size="sm" onClick={logout}>
              Sign Out
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}


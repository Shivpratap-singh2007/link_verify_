import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { setAuthTokenGetter } from "@/lib/apiClient";
import { isSupabaseConfigured, supabase } from "@/lib/supabase";
import { api } from "@/services/api";
import type { UserProfile } from "@/types/api";

interface AuthContextValue {
  user: UserProfile | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  authMode: "supabase" | "local_jwt";
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, displayName: string) => Promise<{ needsEmailConfirmation?: boolean }>;
  logout: () => Promise<void>;
  sendPasswordReset: (email: string, newPassword?: string) => Promise<string>;
  updateDisplayName: (displayName: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);
const LOCAL_TOKEN_KEY = "link-verify-access-token";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [token, setToken] = useState<string | null>(() => {
    if (isSupabaseConfigured) return null;
    return localStorage.getItem(LOCAL_TOKEN_KEY);
  });
  const [isLoading, setIsLoading] = useState(true);
  const tokenRef = useRef<string | null>(token);

  useEffect(() => {
    tokenRef.current = token;
  }, [token]);

  useEffect(() => {
    setAuthTokenGetter(() => tokenRef.current);
  }, []);

  useEffect(() => {
    let active = true;

    async function hydrate() {
      if (isSupabaseConfigured && supabase) {
        const { data } = await supabase.auth.getSession();
        const accessToken = data.session?.access_token ?? null;
        tokenRef.current = accessToken;
        if (active) setToken(accessToken);

        if (accessToken && data.session?.user) {
          try {
            const profile = await api.getMyProfile();
            if (active) setUser(profile);
          } catch {
            if (active) {
              setUser({
                id: data.session.user.id,
                email: data.session.user.email ?? "",
                display_name:
                  (data.session.user.user_metadata?.display_name as string | undefined) ||
                  (data.session.user.email?.split("@")[0] ?? "User"),
                auth_provider: "supabase",
                created_at: data.session.user.created_at,
              });
            }
          }
        }
        if (active) setIsLoading(false);
        return;
      }

      // Local JWT mode hydration
      const storedToken = localStorage.getItem(LOCAL_TOKEN_KEY);
      if (!storedToken) {
        if (active) setIsLoading(false);
        return;
      }
      tokenRef.current = storedToken;
      try {
        const profile = await api.getMyProfile();
        if (active) {
          setToken(storedToken);
          setUser(profile);
        }
      } catch {
        localStorage.removeItem(LOCAL_TOKEN_KEY);
        tokenRef.current = null;
        if (active) {
          setToken(null);
          setUser(null);
        }
      } finally {
        if (active) setIsLoading(false);
      }
    }

    hydrate();

    if (isSupabaseConfigured && supabase) {
      const { data: sub } = supabase.auth.onAuthStateChange((_event, session) => {
        const nextToken = session?.access_token ?? null;
        tokenRef.current = nextToken;
        setToken(nextToken);
        if (!session?.user) {
          setUser(null);
        } else {
          api
            .getMyProfile()
            .then(setUser)
            .catch(() =>
              setUser({
                id: session.user.id,
                email: session.user.email ?? "",
                display_name:
                  (session.user.user_metadata?.display_name as string | undefined) ||
                  (session.user.email?.split("@")[0] ?? "User"),
                auth_provider: "supabase",
                created_at: session.user.created_at,
              }),
            );
        }
      });
      return () => {
        active = false;
        sub.subscription.unsubscribe();
      };
    }

    return () => {
      active = false;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    if (isSupabaseConfigured && supabase) {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) throw new Error(error.message);
      const accessToken = data.session?.access_token ?? null;
      tokenRef.current = accessToken;
      setToken(accessToken);
      const profile = await api.getMyProfile();
      setUser(profile);
      return;
    }

    const res = await api.loginLocal({ email, password });
    localStorage.setItem(LOCAL_TOKEN_KEY, res.access_token);
    tokenRef.current = res.access_token;
    setToken(res.access_token);
    setUser(res.user);
  }, []);

  const register = useCallback(async (email: string, password: string, displayName: string) => {
    if (isSupabaseConfigured && supabase) {
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: { data: { display_name: displayName } },
      });
      if (error) throw new Error(error.message);
      if (!data.session) {
        return { needsEmailConfirmation: true };
      }
      const accessToken = data.session.access_token;
      tokenRef.current = accessToken;
      setToken(accessToken);
      const profile = await api.getMyProfile();
      setUser(profile);
      return {};
    }

    const res = await api.registerLocal({ email, password, display_name: displayName });
    localStorage.setItem(LOCAL_TOKEN_KEY, res.access_token);
    tokenRef.current = res.access_token;
    setToken(res.access_token);
    setUser(res.user);
    return {};
  }, []);

  const logout = useCallback(async () => {
    if (isSupabaseConfigured && supabase) {
      await supabase.auth.signOut();
    }
    localStorage.removeItem(LOCAL_TOKEN_KEY);
    tokenRef.current = null;
    setToken(null);
    setUser(null);
  }, []);

  const sendPasswordReset = useCallback(async (email: string, newPassword?: string) => {
    if (isSupabaseConfigured && supabase) {
      const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${window.location.origin}/reset-password`,
      });
      if (error) throw new Error(error.message);
      return "Password reset email sent. Check your inbox.";
    }
    const res = await api.resetPasswordLocal({ email, new_password: newPassword });
    return res.message;
  }, []);

  const updateDisplayName = useCallback(async (displayName: string) => {
    const updated = await api.updateMyProfile(displayName);
    setUser(updated);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        isAuthenticated: Boolean(user && token),
        authMode: isSupabaseConfigured ? "supabase" : "local_jwt",
        login,
        register,
        logout,
        sendPasswordReset,
        updateDisplayName,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}


import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api, configureApi, type Role, type Session } from "./api";

const STORAGE_KEY = "weblock.session";

interface AuthState {
  session: Session | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState>({
  session: null,
  login: async () => {},
  logout: () => {},
});

function loadSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }): React.JSX.Element {
  const [session, setSession] = useState<Session | null>(loadSession);

  const logout = useCallback(() => {
    setSession((current) => {
      if (current) void api.logout(current.refreshToken);
      return null;
    });
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    configureApi(
      () => loadSession()?.accessToken ?? null,
      () => {
        try {
          sessionStorage.removeItem(STORAGE_KEY);
        } catch {
          /* ignore */
        }
        setSession(null);
      },
    );
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const resp = await api.login(email, password);
    const next: Session = {
      accessToken: resp.access_token,
      refreshToken: resp.refresh_token,
      role: resp.role,
      orgId: resp.org_id,
      email,
    };
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      /* private mode: memory only */
    }
    setSession(next);
  }, []);

  const value = useMemo(() => ({ session, login, logout }), [session, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}

export function canWrite(role: Role | undefined): boolean {
  return role === "admin" || role === "analyst" || role === "investigator";
}

export function canRespond(role: Role | undefined): boolean {
  return role === "admin" || role === "analyst" || role === "investigator";
}

export function isAdmin(role: Role | undefined): boolean {
  return role === "admin";
}

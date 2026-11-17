import { createContext, useContext, useEffect, useState } from "react";
import { api } from "@/lib/api";

const AuthCtx = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null); // null=checking, false=unauth
  useEffect(() => {
    api.me().then(setUser).catch(() => setUser(false));
  }, []);
  const login = async (email, password) => {
    const u = await api.login(email, password);
    setUser(u); return u;
  };
  const logout = async () => {
    try { await api.logout(); } catch (e) {}
    setUser(false);
  };
  return <AuthCtx.Provider value={{ user, setUser, login, logout }}>{children}</AuthCtx.Provider>;
}

export const useAuth = () => useContext(AuthCtx);
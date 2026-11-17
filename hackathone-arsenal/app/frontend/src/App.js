import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import { Toaster } from "sonner";

function Protected({ children }) {
  const { user } = useAuth();
  if (user === null) return <div className="min-h-screen flex items-center justify-center text-cyan-400 font-mono text-xs tracking-widest uppercase">Initializing session…</div>;
  if (!user) return <Navigate to="/" replace />;
  return children;
}

function Public({ children }) {
  const { user } = useAuth();
  if (user === null) return null;
  if (user) return <Navigate to="/dashboard" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Toaster theme="dark" position="bottom-right" toastOptions={{ style: { background: "#0D1117", border: "1px solid rgba(62,232,255,0.25)", color: "#F1F5F9", fontFamily: "JetBrains Mono, monospace", fontSize: 12 } }} />
        <Routes>
          <Route path="/" element={<Public><Login /></Public>} />
          <Route path="/dashboard" element={<Protected><Dashboard /></Protected>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
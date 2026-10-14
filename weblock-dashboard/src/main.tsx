import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import { Shell } from "./ui";
import { LoginPage } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { IncidentsPage } from "./pages/Incidents";
import { IncidentDetailPage } from "./pages/IncidentDetail";
import { DetectionsPage, CorrelationsPage } from "./pages/Detections";
import { EndpointsPage, EndpointDetailPage } from "./pages/Endpoints";
import { ResponsePage } from "./pages/Response";
import { AIPage } from "./pages/AI";
import { ReportsPage } from "./pages/Reports";
import { AuditPage } from "./pages/Audit";
import "./styles.css";

function RequireAuth({ children }: { children: React.JSX.Element }): React.JSX.Element {
  const { session } = useAuth();
  const location = useLocation();
  if (!session) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <Shell>{children}</Shell>;
}

function AppRoutes(): React.JSX.Element {
  const { session } = useAuth();
  return (
    <Routes>
      <Route
        path="/login"
        element={session ? <Navigate to="/" replace /> : <LoginPage />}
      />
      <Route path="/" element={<RequireAuth><OverviewPage /></RequireAuth>} />
      <Route path="/incidents" element={<RequireAuth><IncidentsPage /></RequireAuth>} />
      <Route path="/incidents/:id" element={<RequireAuth><IncidentDetailPage /></RequireAuth>} />
      <Route path="/detections" element={<RequireAuth><DetectionsPage /></RequireAuth>} />
      <Route path="/correlations" element={<RequireAuth><CorrelationsPage /></RequireAuth>} />
      <Route path="/endpoints" element={<RequireAuth><EndpointsPage /></RequireAuth>} />
      <Route path="/endpoints/:id" element={<RequireAuth><EndpointDetailPage /></RequireAuth>} />
      <Route path="/response" element={<RequireAuth><ResponsePage /></RequireAuth>} />
      <Route path="/ai" element={<RequireAuth><AIPage /></RequireAuth>} />
      <Route path="/reports" element={<RequireAuth><ReportsPage /></RequireAuth>} />
      <Route path="/audit" element={<RequireAuth><AuditPage /></RequireAuth>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
);

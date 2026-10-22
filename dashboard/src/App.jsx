import React from 'react';
import { Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { useAuth } from './auth/AuthContext';
import { Navbar } from './components/Navbar';
import { Overview } from './pages/Overview';
import { Alerts } from './pages/Alerts';
import { AlertDetail } from './pages/AlertDetail';
import { Devices } from './pages/Devices';
import { Rules } from './pages/Rules';
import { Login } from './pages/Login';

// Protected layout wrapping Navbar and child routes
const ProtectedLayout = () => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#080b12',
        color: 'var(--text-muted)',
      }}>
        Loading security session...
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar />
      <main style={{ flex: 1 }}>
        <Outlet />
      </main>
    </div>
  );
};

export const App = () => {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<ProtectedLayout />}>
        <Route path="/" element={<Overview />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/alerts/:id" element={<AlertDetail />} />
        <Route path="/devices" element={<Devices />} />
        <Route path="/rules" element={<Rules />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
};

export default App;

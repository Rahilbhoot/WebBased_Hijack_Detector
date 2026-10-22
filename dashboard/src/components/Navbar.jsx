import React, { useState, useEffect } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { ShieldAlert, Activity, HardDrive, BookOpen, LogOut, Radio, Clock, User } from 'lucide-react';
import { useAuth } from '../auth/AuthContext';

export const Navbar = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [time, setTime] = useState(new Date().toUTCString());

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toUTCString().replace('GMT', 'UTC'));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header style={{
      borderBottom: '1px solid var(--border-card)',
      background: 'rgba(10, 15, 26, 0.85)',
      backdropFilter: 'blur(16px)',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      padding: '0 24px',
    }}>
      <div style={{
        maxWidth: 1440,
        margin: '0 auto',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        height: 68,
      }}>
        {/* Brand / Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 40,
            height: 40,
            borderRadius: 10,
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.25) 0%, rgba(6, 182, 212, 0.25) 100%)',
            border: '1px solid rgba(99, 102, 241, 0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#818cf8',
          }}>
            <ShieldAlert size={22} />
          </div>
          <div>
            <div style={{
              fontFamily: 'var(--font-display)',
              fontWeight: 800,
              fontSize: '1.05rem',
              letterSpacing: '-0.02em',
              background: 'linear-gradient(135deg, #ffffff 40%, #94a3b8 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}>
              HIJACK DETECTOR
            </div>
            <div style={{
              fontSize: '0.68rem',
              fontWeight: 600,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: 'var(--text-dim)',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}>
              <span className="dot-pulse" style={{ color: '#10b981', width: 6, height: 6 }} />
              Windows Log SOC v1.0
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <NavLink
            to="/"
            end
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '8px 14px',
              borderRadius: 'var(--radius-md)',
              textDecoration: 'none',
              fontSize: '0.88rem',
              fontWeight: 600,
              color: isActive ? '#ffffff' : 'var(--text-muted)',
              background: isActive ? 'rgba(99, 102, 241, 0.15)' : 'transparent',
              border: isActive ? '1px solid rgba(99, 102, 241, 0.35)' : '1px solid transparent',
              transition: 'all 0.15s ease',
            })}
          >
            <Activity size={17} />
            <span>Overview</span>
          </NavLink>

          <NavLink
            to="/alerts"
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '8px 14px',
              borderRadius: 'var(--radius-md)',
              textDecoration: 'none',
              fontSize: '0.88rem',
              fontWeight: 600,
              color: isActive ? '#ffffff' : 'var(--text-muted)',
              background: isActive ? 'rgba(239, 68, 68, 0.15)' : 'transparent',
              border: isActive ? '1px solid rgba(239, 68, 68, 0.35)' : '1px solid transparent',
              transition: 'all 0.15s ease',
            })}
          >
            <Radio size={17} />
            <span>Alerts Explorer</span>
          </NavLink>

          <NavLink
            to="/devices"
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '8px 14px',
              borderRadius: 'var(--radius-md)',
              textDecoration: 'none',
              fontSize: '0.88rem',
              fontWeight: 600,
              color: isActive ? '#ffffff' : 'var(--text-muted)',
              background: isActive ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
              border: isActive ? '1px solid rgba(6, 182, 212, 0.35)' : '1px solid transparent',
              transition: 'all 0.15s ease',
            })}
          >
            <HardDrive size={17} />
            <span>Endpoints Fleet</span>
          </NavLink>

          <NavLink
            to="/rules"
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '8px 14px',
              borderRadius: 'var(--radius-md)',
              textDecoration: 'none',
              fontSize: '0.88rem',
              fontWeight: 600,
              color: isActive ? '#ffffff' : 'var(--text-muted)',
              background: isActive ? 'rgba(168, 85, 247, 0.15)' : 'transparent',
              border: isActive ? '1px solid rgba(168, 85, 247, 0.35)' : '1px solid transparent',
              transition: 'all 0.15s ease',
            })}
          >
            <BookOpen size={17} />
            <span>Rules & Intel</span>
          </NavLink>
        </nav>

        {/* Right Info: Live UTC Clock & User Profile */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '6px 12px',
            borderRadius: 'var(--radius-md)',
            background: 'rgba(0, 0, 0, 0.35)',
            border: '1px solid var(--border-subtle)',
            fontSize: '0.78rem',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-muted)',
          }}>
            <Clock size={14} style={{ color: 'var(--accent-cyan)' }} />
            <span>{time}</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '4px 10px',
              borderRadius: 'var(--radius-full)',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border-subtle)',
            }}>
              <div style={{
                width: 26,
                height: 26,
                borderRadius: '50%',
                background: 'linear-gradient(135deg, #4f46e5, #06b6d4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#fff',
              }}>
                <User size={14} />
              </div>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-main)' }}>
                {user?.username || 'SecOps Admin'}
              </div>
            </div>

            <button
              onClick={handleLogout}
              title="Sign Out"
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-dim)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                padding: 6,
                borderRadius: 'var(--radius-sm)',
                transition: 'color 0.15s ease',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = '#ef4444')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-dim)')}
            >
              <LogOut size={18} />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};

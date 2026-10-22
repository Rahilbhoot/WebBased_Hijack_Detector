import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, Lock, User, KeyRound, AlertCircle, ArrowRight, Sparkles } from 'lucide-react';
import { useAuth } from '../auth/AuthContext';

export const Login = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('Admin123!');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const result = await login(username, password);
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error || 'Invalid credentials or Cognito authentication rejected.');
      }
    } catch (err) {
      setError(err.message || 'Login encountered an unexpected error.');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoFill = () => {
    setUsername('admin');
    setPassword('Admin123!');
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 24,
      background: 'radial-gradient(circle at 50% 30%, rgba(99, 102, 241, 0.12) 0%, transparent 60%), #080b12',
    }}>
      <div className="glass-panel" style={{
        maxWidth: 440,
        width: '100%',
        padding: 36,
        background: 'rgba(15, 23, 42, 0.75)',
        border: '1px solid rgba(99, 102, 241, 0.3)',
        boxShadow: '0 24px 60px rgba(0, 0, 0, 0.7), 0 0 30px rgba(99, 102, 241, 0.15)',
      }}>
        {/* Logo & Headline */}
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{
            width: 56,
            height: 56,
            borderRadius: 14,
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.3) 0%, rgba(6, 182, 212, 0.3) 100%)',
            border: '1px solid rgba(99, 102, 241, 0.5)',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#818cf8',
            marginBottom: 16,
          }}>
            <ShieldAlert size={30} />
          </div>

          <h1 style={{ fontSize: '1.45rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: 6 }}>
            HIJACK DETECTOR SOC
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            Enterprise Windows Log & Browser Attack Monitor
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.35)',
            borderRadius: 'var(--radius-md)',
            padding: '10px 14px',
            marginBottom: 20,
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            color: '#fca5a5',
            fontSize: '0.82rem',
          }}>
            <AlertCircle size={16} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', marginBottom: 6 }}>
              COGNITO USERNAME / EMAIL:
            </label>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              background: 'rgba(0, 0, 0, 0.4)',
              border: '1px solid var(--border-card)',
              borderRadius: 'var(--radius-md)',
              padding: '10px 14px',
            }}>
              <User size={16} style={{ color: 'var(--text-dim)' }} />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin or user@domain.com"
                style={{
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  color: '#ffffff',
                  fontSize: '0.9rem',
                  width: '100%',
                }}
              />
            </div>
          </div>

          <div style={{ marginBottom: 24 }}>
            <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', marginBottom: 6 }}>
              PASSWORD:
            </label>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              background: 'rgba(0, 0, 0, 0.4)',
              border: '1px solid var(--border-card)',
              borderRadius: 'var(--radius-md)',
              padding: '10px 14px',
            }}>
              <Lock size={16} style={{ color: 'var(--text-dim)' }} />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                style={{
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  color: '#ffffff',
                  fontSize: '0.9rem',
                  width: '100%',
                }}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary"
            style={{ width: '100%', justifyContent: 'center', padding: '12px 16px', fontSize: '0.92rem' }}
          >
            <span>{loading ? 'Authenticating with Cognito...' : 'Sign In to Console'}</span>
            <ArrowRight size={16} />
          </button>
        </form>

        {/* Demo Mode Helper */}
        <div style={{
          marginTop: 24,
          paddingTop: 18,
          borderTop: '1px solid var(--border-subtle)',
          textAlign: 'center',
        }}>
          <button
            type="button"
            onClick={handleDemoFill}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--accent-indigo)',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <Sparkles size={14} />
            <span>Autofill Demo Credentials (admin / Admin123!)</span>
          </button>
        </div>
      </div>
    </div>
  );
};

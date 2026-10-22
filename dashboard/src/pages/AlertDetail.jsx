import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldAlert,
  Clock,
  HardDrive,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Terminal,
  Activity,
  FileCode,
  Tag,
  Crosshair,
} from 'lucide-react';
import { ApiClient } from '../api/client';

export const AlertDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [showRawJson, setShowRawJson] = useState(true);

  useEffect(() => {
    const loadDetail = async () => {
      try {
        const data = await ApiClient.getAlertDetail(id);
        setAlert(data);
      } catch (err) {
        console.error('Failed to load alert detail:', err);
      } finally {
        setLoading(false);
      }
    };
    loadDetail();
  }, [id]);

  const handleCopyJson = () => {
    if (!alert) return;
    const jsonStr = JSON.stringify(alert.raw_event || alert, null, 2);
    navigator.clipboard.writeText(jsonStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 400 }}>
        <div style={{ color: 'var(--text-muted)' }}>Loading incident forensic dossier...</div>
      </div>
    );
  }

  if (!alert) {
    return (
      <div style={{ maxWidth: 1000, margin: '60px auto', textAlign: 'center' }}>
        <h2 style={{ marginBottom: 12 }}>Incident Dossier Not Found</h2>
        <p style={{ color: 'var(--text-muted)', marginBottom: 20 }}>
          Alert ID <code style={{ color: 'var(--accent-cyan)' }}>{id}</code> could not be found or has expired from retention.
        </p>
        <button onClick={() => navigate('/alerts')} className="btn-primary">
          Back to Alerts Console
        </button>
      </div>
    );
  }

  const badgeClass =
    alert.severity === 'High' ? 'badge badge-high' :
    alert.severity === 'Medium' ? 'badge badge-medium' :
    'badge badge-low';

  const raw = alert.raw_event || {};
  const timeline = alert.timeline || [];

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', padding: '32px 24px' }}>
      {/* Back button */}
      <div style={{ marginBottom: 20 }}>
        <button
          onClick={() => navigate('/alerts')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
            fontSize: '0.88rem',
            fontWeight: 600,
            cursor: 'pointer',
            padding: 0,
          }}
          onMouseEnter={(e) => (e.currentTarget.style.color = '#ffffff')}
          onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
        >
          <ArrowLeft size={16} />
          <span>Back to Alerts Explorer</span>
        </button>
      </div>

      {/* Hero Incident Header */}
      <div className="glass-panel" style={{
        padding: 28,
        marginBottom: 24,
        borderLeft: alert.severity === 'High' ? '4px solid #ef4444' : alert.severity === 'Medium' ? '4px solid #f59e0b' : '4px solid #10b981',
      }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
              <span className={badgeClass}>{alert.severity}</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                INCIDENT ID: {alert.alert_id}
              </span>
            </div>
            <h1 style={{ fontSize: '1.6rem', marginBottom: 8 }}>
              {alert.rule_ids?.[0] ? `${alert.rule_ids.join(' + ')} Detection` : 'Suspicious Endpoint Activity'}
            </h1>
            <div style={{ display: 'flex', alignItems: 'center', gap: 20, color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <HardDrive size={15} style={{ color: 'var(--accent-cyan)' }} />
                <span>Endpoint: <strong style={{ color: '#ffffff' }}>{alert.device_id}</strong></span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Clock size={15} style={{ color: 'var(--accent-indigo)' }} />
                <span>{new Date(alert.timestamp).toUTCString()}</span>
              </div>
            </div>
          </div>

          {/* Risk Score Gauge */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'rgba(0, 0, 0, 0.4)',
            border: '1px solid var(--border-card)',
            borderRadius: 'var(--radius-lg)',
            padding: '14px 24px',
            minWidth: 120,
          }}>
            <span style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-dim)' }}>
              Risk Score
            </span>
            <span style={{
              fontSize: '2.4rem',
              fontWeight: 800,
              fontFamily: 'var(--font-display)',
              color: alert.score >= 60 ? '#f87171' : alert.score >= 30 ? '#fbbf24' : '#34d399',
            }}>
              {alert.score}
            </span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
              / 100 max
            </span>
          </div>
        </div>
      </div>

      {/* Narrative & MITRE Mapping Card */}
      <div className="glass-panel" style={{ padding: 24, marginBottom: 24 }}>
        <h3 style={{ fontSize: '1.1rem', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Crosshair size={18} style={{ color: 'var(--accent-indigo)' }} />
          Threat Analysis & Explanation
        </h3>
        <p style={{ fontSize: '0.95rem', color: '#e2e8f0', lineHeight: 1.6, marginBottom: 16 }}>
          {alert.explanation}
        </p>

        {/* MITRE Badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)', marginRight: 4 }}>
            MITRE ATT&CK:
          </span>
          {(alert.mitre_ids || []).map((mitre) => (
            <div key={mitre} style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              background: 'rgba(99, 102, 241, 0.15)',
              border: '1px solid rgba(99, 102, 241, 0.35)',
              padding: '4px 10px',
              borderRadius: 'var(--radius-sm)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.78rem',
              color: '#c7d2fe',
            }}>
              <Tag size={12} />
              <span>{mitre}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Forensic Evidence Table */}
      <div className="glass-panel" style={{ padding: 24, marginBottom: 24 }}>
        <h3 style={{ fontSize: '1.1rem', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Terminal size={18} style={{ color: 'var(--accent-cyan)' }} />
          Forensic Artifact Details
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
          {raw.process_image && (
            <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: 12, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 4 }}>
                Process Image
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: '#ffffff', wordBreak: 'break-all' }}>
                {raw.process_image}
              </div>
            </div>
          )}

          {raw.parent_image && (
            <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: 12, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 4 }}>
                Parent Process
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: '#ffffff', wordBreak: 'break-all' }}>
                {raw.parent_image}
              </div>
            </div>
          )}

          {raw.user && (
            <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: 12, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 4 }}>
                User Context
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--accent-cyan)' }}>
                {raw.user}
              </div>
            </div>
          )}

          {raw.file_path && (
            <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: 12, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 4 }}>
                Target File
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: '#fbbf24', wordBreak: 'break-all' }}>
                {raw.file_path}
              </div>
            </div>
          )}

          {raw.target_object && (
            <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: 12, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 4 }}>
                Registry Target Object
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: '#a855f7', wordBreak: 'break-all' }}>
                {raw.target_object}
              </div>
            </div>
          )}
        </div>

        {raw.command_line && (
          <div style={{ marginTop: 16 }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 6 }}>
              Command Line Arguments
            </div>
            <div className="code-box" style={{ background: '#030712' }}>
              {raw.command_line}
            </div>
          </div>
        )}
      </div>

      {/* Correlated Event Timeline */}
      <div className="glass-panel" style={{ padding: 24, marginBottom: 24 }}>
        <h3 style={{ fontSize: '1.1rem', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Activity size={18} style={{ color: 'var(--accent-purple)' }} />
          Correlated Timeline (±10 Minute Window)
        </h3>
        <p style={{ color: 'var(--text-dim)', fontSize: '0.82rem', marginBottom: 20 }}>
          Chronological sequence of forensic events leading up to or following this detection
        </p>

        {timeline.length === 0 ? (
          <div style={{ color: 'var(--text-dim)', fontSize: '0.85rem', fontStyle: 'italic' }}>
            No adjacent correlation events identified within the 10-minute sliding window.
          </div>
        ) : (
          <div style={{ position: 'relative', paddingLeft: 24 }}>
            {/* Vertical timeline bar */}
            <div style={{
              position: 'absolute',
              left: 7,
              top: 10,
              bottom: 10,
              width: 2,
              background: 'linear-gradient(180deg, #6366f1 0%, #a855f7 100%)',
            }} />

            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {timeline.map((item, idx) => {
                const isTrigger = item.is_trigger;
                return (
                  <div key={idx} style={{ position: 'relative' }}>
                    {/* Circle Node */}
                    <div style={{
                      position: 'absolute',
                      left: -24,
                      top: 4,
                      width: 14,
                      height: 14,
                      borderRadius: '50%',
                      background: isTrigger ? '#ef4444' : '#6366f1',
                      border: '3px solid #080b12',
                      boxShadow: isTrigger ? '0 0 10px #ef4444' : '0 0 6px #6366f1',
                    }} />

                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                          {new Date(item.timestamp).toLocaleTimeString()}
                        </span>
                        {isTrigger && (
                          <span className="badge badge-high" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>
                            ATTACK TRIGGER
                          </span>
                        )}
                        <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#ffffff' }}>
                          {item.title}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.84rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>
                        {item.description}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Raw Event Telemetry (Collapsible) */}
      <div className="glass-panel" style={{ padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <button
            onClick={() => setShowRawJson(!showRawJson)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              background: 'transparent',
              border: 'none',
              color: '#ffffff',
              fontSize: '1rem',
              fontWeight: 700,
              cursor: 'pointer',
              padding: 0,
            }}
          >
            <FileCode size={18} style={{ color: 'var(--accent-blue)' }} />
            <span>Raw Event Telemetry JSON</span>
            {showRawJson ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>

          <button
            onClick={handleCopyJson}
            className="btn-secondary"
            style={{ fontSize: '0.78rem', padding: '6px 12px' }}
          >
            {copied ? <Check size={14} style={{ color: '#10b981' }} /> : <Copy size={14} />}
            <span>{copied ? 'Copied to Clipboard!' : 'Copy JSON'}</span>
          </button>
        </div>

        {showRawJson && (
          <div className="code-box" style={{ maxHeight: 360, overflowY: 'auto' }}>
            <pre style={{ margin: 0 }}>
              {JSON.stringify(alert.raw_event || alert, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};

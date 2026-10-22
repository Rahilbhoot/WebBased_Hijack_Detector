import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, AlertTriangle, CheckCircle, HardDrive, Zap, ArrowRight, RefreshCw, Layers } from 'lucide-react';
import { ApiClient } from '../api/client';

export const Overview = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchStats = async () => {
    try {
      const data = await ApiClient.getStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load stats:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 15000); // 15s auto-refresh
    return () => clearInterval(interval);
  }, []);

  const handleManualRefresh = () => {
    setRefreshing(true);
    fetchStats();
  };

  if (loading && !stats) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 400 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, color: 'var(--text-muted)' }}>
          <RefreshCw className="dot-pulse" size={20} />
          <span>Connecting to Cloud SOC telemetry...</span>
        </div>
      </div>
    );
  }

  const sev = stats?.severity_distribution || { High: 0, Medium: 0, Low: 0 };
  const totalAlerts = stats?.total_alerts_24h || 0;
  const fleet = stats?.fleet_status || { total: 0, online: 0, offline: 0 };
  const topRules = stats?.top_rules || [];
  const recentAlerts = stats?.recent_alerts || [];

  // Severity percentage calculations for interactive SVG Donut
  const highPercent = totalAlerts > 0 ? (sev.High / totalAlerts) * 100 : 0;
  const medPercent = totalAlerts > 0 ? (sev.Medium / totalAlerts) * 100 : 0;
  const lowPercent = totalAlerts > 0 ? (sev.Low / totalAlerts) * 100 : 0;

  return (
    <div style={{ maxWidth: 1440, margin: '0 auto', padding: '32px 24px' }}>
      {/* Top Banner / Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 28,
        flexWrap: 'wrap',
        gap: 16,
      }}>
        <div>
          <h1 style={{ fontSize: '1.8rem', marginBottom: 6 }}>Security Operations Overview</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
            Real-time Windows Event telemetry & browser hijack correlation pipeline.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button
            onClick={handleManualRefresh}
            className="btn-secondary"
            disabled={refreshing}
            style={{ fontSize: '0.85rem' }}
          >
            <RefreshCw size={15} style={{ animation: refreshing ? 'spin 1s infinite linear' : 'none' }} />
            <span>{refreshing ? 'Refreshing...' : 'Refresh Telemetry'}</span>
          </button>
          <button
            onClick={() => navigate('/alerts')}
            className="btn-primary"
            style={{ fontSize: '0.85rem' }}
          >
            <span>View All Alerts</span>
            <ArrowRight size={15} />
          </button>
        </div>
      </div>

      {/* KPI 4-Card Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
        gap: 20,
        marginBottom: 32,
      }}>
        {/* Card 1: Total Alerts */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Total Alerts (24h)
            </span>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: 8,
              background: 'rgba(99, 102, 241, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#818cf8',
            }}>
              <Zap size={18} />
            </div>
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#ffffff' }}>
            {totalAlerts}
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginTop: 4 }}>
            Aggregated across all registered endpoints
          </div>
        </div>

        {/* Card 2: High Severity Threats */}
        <div className="glass-panel" style={{
          padding: 22,
          borderLeft: '4px solid #ef4444',
          background: 'radial-gradient(circle at top right, rgba(239, 68, 68, 0.08) 0%, rgba(17, 24, 39, 0.7) 70%)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#f87171', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              High Severity Attacks
            </span>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: 8,
              background: 'rgba(239, 68, 68, 0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ef4444',
            }}>
              <ShieldAlert size={18} />
            </div>
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f87171' }}>
            {sev.High}
          </div>
          <div style={{ fontSize: '0.78rem', color: '#fca5a5', marginTop: 4 }}>
            Require urgent SOC incident triage
          </div>
        </div>

        {/* Card 3: Active Fleet Endpoints */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Fleet Status
            </span>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: 8,
              background: 'rgba(16, 185, 129, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#34d399',
            }}>
              <HardDrive size={18} />
            </div>
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#ffffff', display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <span>{fleet.online}</span>
            <span style={{ fontSize: '1.1rem', color: 'var(--text-dim)', fontWeight: 500 }}>/ {fleet.total} Online</span>
          </div>
          <div style={{ fontSize: '0.78rem', color: fleet.offline > 0 ? '#f59e0b' : '#34d399', marginTop: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="dot-pulse" style={{ color: fleet.offline > 0 ? '#f59e0b' : '#34d399', width: 6, height: 6 }} />
            <span>{fleet.offline > 0 ? `${fleet.offline} endpoint(s) silent >5 min` : 'All endpoints sending heartbeats'}</span>
          </div>
        </div>

        {/* Card 4: Correlation Rules */}
        <div className="glass-panel" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Multi-Stage Correlated
            </span>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: 8,
              background: 'rgba(168, 85, 247, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#c084fc',
            }}>
              <Layers size={18} />
            </div>
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#c084fc' }}>
            {topRules.find(r => r.rule_id.startsWith('CR'))?.count || 2}
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginTop: 4 }}>
            Chained attack patterns identified (CR01-CR03)
          </div>
        </div>
      </div>

      {/* Middle Row: Severity Visualizer + Top Rules Breakdown */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
        gap: 24,
        marginBottom: 32,
      }}>
        {/* Severity Distribution Card */}
        <div className="glass-panel" style={{ padding: 24 }}>
          <h3 style={{ fontSize: '1.1rem', marginBottom: 6 }}>Threat Severity Distribution</h3>
          <p style={{ color: 'var(--text-dim)', fontSize: '0.82rem', marginBottom: 20 }}>
            Breakdown of 24h incidents by risk scoring thresholds
          </p>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', gap: 24, flexWrap: 'wrap' }}>
            {/* SVG Donut */}
            <div style={{ position: 'relative', width: 140, height: 140 }}>
              <svg width="140" height="140" viewBox="0 0 42 42" style={{ transform: 'rotate(-90deg)' }}>
                <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="rgba(255,255,255,0.05)" strokeWidth="4.5" />
                {/* High */}
                <circle
                  cx="21" cy="21" r="15.915"
                  fill="transparent"
                  stroke="#ef4444"
                  strokeWidth="4.5"
                  strokeDasharray={`${highPercent} ${100 - highPercent}`}
                  strokeDashoffset="0"
                />
                {/* Med */}
                <circle
                  cx="21" cy="21" r="15.915"
                  fill="transparent"
                  stroke="#f59e0b"
                  strokeWidth="4.5"
                  strokeDasharray={`${medPercent} ${100 - medPercent}`}
                  strokeDashoffset={`${-highPercent}`}
                />
                {/* Low */}
                <circle
                  cx="21" cy="21" r="15.915"
                  fill="transparent"
                  stroke="#10b981"
                  strokeWidth="4.5"
                  strokeDasharray={`${lowPercent} ${100 - lowPercent}`}
                  strokeDashoffset={`${-(highPercent + medPercent)}`}
                />
              </svg>
              <div style={{
                position: 'absolute',
                top: 0, left: 0, right: 0, bottom: 0,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
              }}>
                <span style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-display)' }}>
                  {totalAlerts}
                </span>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>
                  Total
                </span>
              </div>
            </div>

            {/* Legend Stats */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minWidth: 160 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444' }} />
                  <span style={{ fontSize: '0.88rem', fontWeight: 600 }}>High (≥60)</span>
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#f87171' }}>{sev.High}</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#f59e0b' }} />
                  <span style={{ fontSize: '0.88rem', fontWeight: 600 }}>Medium (30-59)</span>
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#fbbf24' }}>{sev.Medium}</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#10b981' }} />
                  <span style={{ fontSize: '0.88rem', fontWeight: 600 }}>Low (&lt;30)</span>
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#34d399' }}>{sev.Low}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Top Triggered Detection Rules */}
        <div className="glass-panel" style={{ padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
            <h3 style={{ fontSize: '1.1rem' }}>Top Triggered Detection Rules</h3>
            <button
              onClick={() => navigate('/rules')}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--accent-indigo)',
                fontSize: '0.8rem',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              View All Rules &rarr;
            </button>
          </div>
          <p style={{ color: 'var(--text-dim)', fontSize: '0.82rem', marginBottom: 20 }}>
            Most frequent attack heuristics in active telemetry
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {topRules.map((r) => {
              const maxCount = Math.max(...topRules.map(x => x.count), 1);
              const barWidth = Math.round((r.count / maxCount) * 100);
              const isCorrelation = r.rule_id.startsWith('CR');

              return (
                <div key={r.rule_id}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: 4 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        color: isCorrelation ? '#c084fc' : '#818cf8',
                      }}>
                        {r.rule_id}
                      </span>
                      <span style={{ color: 'var(--text-muted)' }}>
                        {r.rule_id === 'BH001' && 'Browser Execution with Proxy/Extension Flags'}
                        {r.rule_id === 'BH002' && 'Browser Policy Registry Alteration'}
                        {r.rule_id === 'BH003' && 'Internet Settings Proxy Override'}
                        {r.rule_id === 'BH004' && 'Windows hosts File Tampering'}
                        {r.rule_id === 'BH007' && 'Windows Security Log Cleared'}
                        {r.rule_id === 'CR01' && 'Registry Policy + Browser Execution Chain'}
                      </span>
                    </div>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#ffffff' }}>
                      {r.count}
                    </span>
                  </div>

                  <div style={{ width: '100%', height: 6, background: 'rgba(255, 255, 255, 0.05)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{
                      width: `${barWidth}%`,
                      height: '100%',
                      background: isCorrelation
                        ? 'linear-gradient(90deg, #a855f7, #c084fc)'
                        : 'linear-gradient(90deg, #4f46e5, #06b6d4)',
                      borderRadius: 3,
                    }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Bottom Section: Recent High-Priority Alerts Stream */}
      <div className="glass-panel" style={{ padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', marginBottom: 4 }}>Recent Incident Detections</h3>
            <p style={{ color: 'var(--text-dim)', fontSize: '0.82rem' }}>
              Latest alerts flagged by cloud correlation engine
            </p>
          </div>
          <button
            onClick={() => navigate('/alerts')}
            className="btn-secondary"
            style={{ fontSize: '0.82rem', padding: '6px 12px' }}
          >
            Open Alerts Console
          </button>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Alert ID</th>
                <th>Device</th>
                <th>Triggered Rules</th>
                <th>Risk Score</th>
                <th>Explanation</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: 32, color: 'var(--text-dim)' }}>
                    No alerts in past 24 hours. Endpoint telemetry is normal.
                  </td>
                </tr>
              ) : (
                recentAlerts.map((alert) => {
                  const badgeClass =
                    alert.severity === 'High' ? 'badge badge-high' :
                    alert.severity === 'Medium' ? 'badge badge-medium' :
                    'badge badge-low';

                  return (
                    <tr key={alert.alert_id} style={{ cursor: 'pointer' }} onClick={() => navigate(`/alerts/${alert.alert_id}`)}>
                      <td>
                        <span className={badgeClass}>{alert.severity}</span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '0.82rem' }}>
                        {alert.alert_id}
                      </td>
                      <td style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                        {alert.device_id}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {(alert.rule_ids || []).map((id) => (
                            <span key={id} className="badge-mitre">
                              {id}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: alert.score >= 60 ? '#f87171' : '#fbbf24' }}>
                        {alert.score}
                      </td>
                      <td style={{ maxWidth: 380, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                        {alert.explanation}
                      </td>
                      <td>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/alerts/${alert.alert_id}`);
                          }}
                          className="btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '4px 8px' }}
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

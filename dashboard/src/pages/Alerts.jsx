import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter, ShieldAlert, AlertTriangle, CheckCircle, RefreshCw, ArrowRight, ExternalLink } from 'lucide-react';
import { ApiClient } from '../api/client';

export const Alerts = () => {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedDevice, setSelectedDevice] = useState('ALL');
  const [devices, setDevices] = useState([]);
  const [refreshing, setRefreshing] = useState(false);

  const fetchAlerts = async () => {
    try {
      const params = {};
      if (selectedSeverity !== 'ALL') params.severity = selectedSeverity;
      if (selectedDevice !== 'ALL') params.device_id = selectedDevice;

      const data = await ApiClient.getAlerts(params);
      setAlerts(data.alerts || []);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const fetchDeviceList = async () => {
    try {
      const data = await ApiClient.getDevices();
      setDevices(data.devices || []);
    } catch (e) {
      console.warn('Failed to load devices list:', e);
    }
  };

  useEffect(() => {
    fetchDeviceList();
  }, []);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 8000); // Real-time 8s SOC polling
    return () => clearInterval(interval);
  }, [selectedSeverity, selectedDevice]);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchAlerts();
  };

  // Filter alerts by search query
  const filteredAlerts = alerts.filter((a) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    const idMatch = a.alert_id?.toLowerCase().includes(q);
    const devMatch = a.device_id?.toLowerCase().includes(q);
    const expMatch = a.explanation?.toLowerCase().includes(q);
    const ruleMatch = (a.rule_ids || []).some(r => r.toLowerCase().includes(q));
    const mitreMatch = (a.mitre_ids || []).some(m => m.toLowerCase().includes(q));
    return idMatch || devMatch || expMatch || ruleMatch || mitreMatch;
  });

  return (
    <div style={{ maxWidth: 1440, margin: '0 auto', padding: '32px 24px' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 28,
        flexWrap: 'wrap',
        gap: 16,
      }}>
        <div>
          <h1 style={{ fontSize: '1.8rem', marginBottom: 6 }}>Alerts Explorer</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
            Triaged security incidents detected across monitored Windows endpoints.
          </p>
        </div>

        <button
          onClick={handleRefresh}
          className="btn-secondary"
          disabled={refreshing}
          style={{ fontSize: '0.85rem' }}
        >
          <RefreshCw size={15} style={{ animation: refreshing ? 'spin 1s infinite linear' : 'none' }} />
          <span>{refreshing ? 'Updating...' : 'Refresh List'}</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-panel" style={{
        padding: '16px 20px',
        marginBottom: 24,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 16,
      }}>
        {/* Search Input */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          background: 'rgba(0, 0, 0, 0.35)',
          border: '1px solid var(--border-card)',
          borderRadius: 'var(--radius-md)',
          padding: '8px 14px',
          minWidth: 320,
          flex: 1,
        }}>
          <Search size={16} style={{ color: 'var(--text-dim)' }} />
          <input
            type="text"
            placeholder="Search by ID, rule, device, MITRE technique, or explanation..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: '#ffffff',
              fontSize: '0.88rem',
              width: '100%',
            }}
          />
        </div>

        {/* Filters Group */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
          {/* Severity Pills */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {['ALL', 'High', 'Medium', 'Low'].map((sev) => {
              const active = selectedSeverity === sev;
              return (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  style={{
                    padding: '6px 12px',
                    borderRadius: 'var(--radius-full)',
                    fontSize: '0.78rem',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    border: active
                      ? '1px solid rgba(99, 102, 241, 0.6)'
                      : '1px solid var(--border-subtle)',
                    background: active
                      ? (sev === 'High' ? 'rgba(239, 68, 68, 0.25)' :
                         sev === 'Medium' ? 'rgba(245, 158, 11, 0.25)' :
                         sev === 'Low' ? 'rgba(16, 185, 129, 0.25)' :
                         'rgba(99, 102, 241, 0.25)')
                      : 'rgba(255, 255, 255, 0.03)',
                    color: active ? '#ffffff' : 'var(--text-dim)',
                  }}
                >
                  {sev}
                </button>
              );
            })}
          </div>

          {/* Device Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)', fontWeight: 600 }}>DEVICE:</span>
            <select
              value={selectedDevice}
              onChange={(e) => setSelectedDevice(e.target.value)}
              style={{
                background: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid var(--border-card)',
                color: '#ffffff',
                fontSize: '0.82rem',
                borderRadius: 'var(--radius-md)',
                padding: '6px 12px',
                outline: 'none',
                cursor: 'pointer',
              }}
            >
              <option value="ALL">All Endpoints</option>
              {devices.map((d) => (
                <option key={d.device_id} value={d.device_id}>
                  {d.hostname || d.device_id}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="glass-panel" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-dim)', fontWeight: 600 }}>
            Showing {filteredAlerts.length} incident(s)
          </span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Alert ID</th>
                <th>Timestamp (UTC)</th>
                <th>Device</th>
                <th>Rules & MITRE</th>
                <th>Risk Score</th>
                <th>Incident Narrative</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: 48, color: 'var(--text-dim)' }}>
                    No alerts found matching current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const badgeClass =
                    alert.severity === 'High' ? 'badge badge-high' :
                    alert.severity === 'Medium' ? 'badge badge-medium' :
                    'badge badge-low';

                  const dateFormatted = new Date(alert.timestamp).toLocaleString('en-US', {
                    timeZone: 'UTC',
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                  });

                  return (
                    <tr
                      key={alert.alert_id}
                      style={{ cursor: 'pointer' }}
                      onClick={() => navigate(`/alerts/${alert.alert_id}`)}
                    >
                      <td>
                        <span className={badgeClass}>{alert.severity}</span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '0.82rem' }}>
                        {alert.alert_id}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                        {dateFormatted}
                      </td>
                      <td style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                        {alert.device_id}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                          {(alert.rule_ids || []).map((id) => (
                            <span key={id} className="badge-mitre">
                              {id}
                            </span>
                          ))}
                          {(alert.mitre_ids || []).map((mid) => (
                            <span key={mid} style={{
                              fontSize: '0.7rem',
                              fontFamily: 'var(--font-mono)',
                              background: 'rgba(255, 255, 255, 0.05)',
                              color: 'var(--text-dim)',
                              padding: '2px 6px',
                              borderRadius: 4,
                            }}>
                              {mid}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td style={{
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        color: alert.score >= 60 ? '#f87171' : alert.score >= 30 ? '#fbbf24' : '#34d399',
                      }}>
                        {alert.score}
                      </td>
                      <td style={{
                        maxWidth: 360,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        color: 'var(--text-muted)',
                        fontSize: '0.85rem',
                      }}>
                        {alert.explanation}
                      </td>
                      <td>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/alerts/${alert.alert_id}`);
                          }}
                          className="btn-primary"
                          style={{ fontSize: '0.75rem', padding: '4px 10px' }}
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

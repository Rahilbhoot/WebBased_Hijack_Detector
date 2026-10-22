import React, { useState, useEffect } from 'react';
import { HardDrive, Plus, Key, Trash2, Check, Copy, RefreshCw, AlertTriangle, ShieldCheck, X } from 'lucide-react';
import { ApiClient } from '../api/client';

export const Devices = () => {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [newHostname, setNewHostname] = useState('');
  const [newOsVersion, setNewOsVersion] = useState('Windows 11 Pro 23H2');
  const [generatedKeyInfo, setGeneratedKeyInfo] = useState(null);
  const [keyCopied, setKeyCopied] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const fetchDevices = async () => {
    try {
      const data = await ApiClient.getDevices();
      setDevices(data.devices || []);
    } catch (e) {
      console.error('Failed to load fleet devices:', e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDevices();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchDevices();
  };

  const handleEnrollDevice = async (e) => {
    e.preventDefault();
    if (!newHostname.trim()) return;

    setSubmitting(true);
    try {
      const result = await ApiClient.createDevice({
        hostname: newHostname.trim(),
        os_version: newOsVersion,
      });
      setGeneratedKeyInfo(result);
      fetchDevices();
    } catch (err) {
      alert('Failed to enroll device: ' + err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRevoke = async (deviceId) => {
    if (!window.confirm(`Are you sure you want to REVOKE credentials for endpoint ${deviceId}? This device will be immediately rejected at the API Gateway.`)) {
      return;
    }
    try {
      await ApiClient.revokeDeviceKey(deviceId);
      fetchDevices();
    } catch (err) {
      alert('Failed to revoke device: ' + err.message);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setKeyCopied(true);
    setTimeout(() => setKeyCopied(false), 2000);
  };

  const closeModal = () => {
    setShowModal(false);
    setGeneratedKeyInfo(null);
    setNewHostname('');
  };

  const onlineCount = devices.filter(d => d.status === 'Online').length;
  const offlineCount = devices.filter(d => d.status === 'Offline').length;

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
          <h1 style={{ fontSize: '1.8rem', marginBottom: 6 }}>Endpoints Fleet</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
            Managed Windows hosts running the native Windows Event Log sensor agent.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button
            onClick={handleRefresh}
            className="btn-secondary"
            disabled={refreshing}
            style={{ fontSize: '0.85rem' }}
          >
            <RefreshCw size={15} style={{ animation: refreshing ? 'spin 1s infinite linear' : 'none' }} />
            <span>{refreshing ? 'Updating...' : 'Refresh Fleet'}</span>
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="btn-primary"
            style={{ fontSize: '0.85rem' }}
          >
            <Plus size={16} />
            <span>Enroll New Endpoint</span>
          </button>
        </div>
      </div>

      {/* Fleet Summary Badges */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: 16,
        marginBottom: 24,
      }}>
        <div className="glass-panel" style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 40,
            height: 40,
            borderRadius: 8,
            background: 'rgba(99, 102, 241, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#818cf8',
          }}>
            <HardDrive size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Total Enrolled</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800 }}>{devices.length}</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 40,
            height: 40,
            borderRadius: 8,
            background: 'rgba(16, 185, 129, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#34d399',
          }}>
            <ShieldCheck size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Online (Active)</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#34d399' }}>{onlineCount}</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 40,
            height: 40,
            borderRadius: 8,
            background: 'rgba(245, 158, 11, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#fbbf24',
          }}>
            <AlertTriangle size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Silent / Offline</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#fbbf24' }}>{offlineCount}</div>
          </div>
        </div>
      </div>

      {/* Fleet Table */}
      <div className="glass-panel" style={{ padding: 20 }}>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Device ID</th>
                <th>Hostname</th>
                <th>Operating System</th>
                <th>Agent Version</th>
                <th>Last Heartbeat</th>
                <th>Queue</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {devices.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: 48, color: 'var(--text-dim)' }}>
                    No endpoints registered yet. Click &ldquo;Enroll New Endpoint&rdquo; to add a machine.
                  </td>
                </tr>
              ) : (
                devices.map((device) => {
                  const isOnline = device.status === 'Online';
                  const isRevoked = device.status === 'Revoked';

                  const dateFormatted = device.last_seen
                    ? new Date(device.last_seen).toLocaleString('en-US', {
                        timeZone: 'UTC',
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      }) + ' UTC'
                    : 'Never';

                  return (
                    <tr key={device.device_id}>
                      <td>
                        <span className={
                          isOnline ? 'status-pill status-online' :
                          isRevoked ? 'status-pill status-revoked' :
                          'status-pill status-offline'
                        }>
                          <span className="dot-pulse" style={{
                            color: isOnline ? '#10b981' : isRevoked ? '#ef4444' : '#94a3b8',
                            width: 6,
                            height: 6,
                          }} />
                          {device.status}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '0.82rem', color: 'var(--accent-cyan)' }}>
                        {device.device_id}
                      </td>
                      <td style={{ fontWeight: 600, color: '#ffffff' }}>
                        {device.hostname}
                      </td>
                      <td style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                        {device.os_version || 'Windows 11'}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                        v{device.agent_version || '1.0.0'}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                        {dateFormatted}
                      </td>
                      <td>
                        <span style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.78rem',
                          color: (device.event_queue_size || 0) > 50 ? '#f59e0b' : 'var(--text-dim)',
                        }}>
                          {device.event_queue_size || 0} queued
                        </span>
                      </td>
                      <td>
                        {!isRevoked ? (
                          <button
                            onClick={() => handleRevoke(device.device_id)}
                            className="btn-danger"
                            title="Revoke Endpoint Credentials"
                          >
                            <Trash2 size={13} />
                            <span>Revoke</span>
                          </button>
                        ) : (
                          <span style={{ fontSize: '0.78rem', color: '#ef4444', fontStyle: 'italic' }}>
                            Revoked
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Enroll Device Modal */}
      {showModal && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100,
          padding: 20,
        }}>
          <div className="glass-panel" style={{
            maxWidth: 540,
            width: '100%',
            padding: 28,
            background: '#0d1322',
            border: '1px solid rgba(99, 102, 241, 0.35)',
            boxShadow: '0 20px 50px rgba(0, 0, 0, 0.7)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Key size={20} style={{ color: 'var(--accent-indigo)' }} />
                <h3 style={{ fontSize: '1.2rem' }}>Enroll New Windows Endpoint</h3>
              </div>
              <button
                onClick={closeModal}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            {!generatedKeyInfo ? (
              <form onSubmit={handleEnrollDevice}>
                <div style={{ marginBottom: 16 }}>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6 }}>
                    HOST MACHINE NAME / IDENTIFIER:
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. DESKTOP-FINANCE-02"
                    value={newHostname}
                    onChange={(e) => setNewHostname(e.target.value)}
                    style={{
                      width: '100%',
                      background: 'rgba(0, 0, 0, 0.4)',
                      border: '1px solid var(--border-card)',
                      borderRadius: 'var(--radius-md)',
                      padding: '10px 14px',
                      color: '#ffffff',
                      fontSize: '0.9rem',
                      outline: 'none',
                    }}
                  />
                </div>

                <div style={{ marginBottom: 24 }}>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6 }}>
                    OPERATING SYSTEM:
                  </label>
                  <select
                    value={newOsVersion}
                    onChange={(e) => setNewOsVersion(e.target.value)}
                    style={{
                      width: '100%',
                      background: 'rgba(0, 0, 0, 0.4)',
                      border: '1px solid var(--border-card)',
                      borderRadius: 'var(--radius-md)',
                      padding: '10px 14px',
                      color: '#ffffff',
                      fontSize: '0.9rem',
                      outline: 'none',
                    }}
                  >
                    <option value="Windows 11 Pro 23H2">Windows 11 Pro 23H2</option>
                    <option value="Windows 11 Enterprise">Windows 11 Enterprise</option>
                    <option value="Windows 10 Pro 22H2">Windows 10 Pro 22H2</option>
                    <option value="Windows Server 2022">Windows Server 2022</option>
                  </select>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
                  <button type="button" onClick={closeModal} className="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" disabled={submitting} className="btn-primary">
                    {submitting ? 'Generating Credentials...' : 'Generate API Key & Enroll'}
                  </button>
                </div>
              </form>
            ) : (
              <div>
                <div style={{
                  background: 'rgba(16, 185, 129, 0.1)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  padding: 16,
                  borderRadius: 'var(--radius-md)',
                  marginBottom: 18,
                }}>
                  <div style={{ color: '#34d399', fontWeight: 700, fontSize: '0.9rem', marginBottom: 4 }}>
                    Endpoint Enrolled Successfully!
                  </div>
                  <div style={{ fontSize: '0.82rem', color: '#e2e8f0' }}>
                    Copy this API key now. For zero-trust security, the raw key is never stored in plain text and cannot be retrieved again.
                  </div>
                </div>

                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 6 }}>
                    DEVICE ID:
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.88rem', color: 'var(--accent-cyan)' }}>
                    {generatedKeyInfo.device_id}
                  </div>
                </div>

                <div style={{ marginBottom: 20 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 6 }}>
                    ONE-TIME API KEY:
                  </div>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    background: '#050811',
                    border: '1px solid var(--border-card)',
                    padding: '10px 14px',
                    borderRadius: 'var(--radius-md)',
                  }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#fbbf24', wordBreak: 'break-all' }}>
                      {generatedKeyInfo.api_key}
                    </span>
                    <button
                      onClick={() => copyToClipboard(generatedKeyInfo.api_key)}
                      className="btn-secondary"
                      style={{ padding: '6px 10px', fontSize: '0.75rem', flexShrink: 0, marginLeft: 10 }}
                    >
                      {keyCopied ? <Check size={14} style={{ color: '#10b981' }} /> : <Copy size={14} />}
                      <span>{keyCopied ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                </div>

                <div style={{ marginBottom: 24 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 6 }}>
                    AGENT SETUP SNIPPET:
                  </div>
                  <div className="code-box" style={{ fontSize: '0.75rem', background: '#03060d' }}>
                    HIJACK_DEVICE_ID={generatedKeyInfo.device_id}<br />
                    HIJACK_API_KEY={generatedKeyInfo.api_key}<br />
                    HIJACK_API_ENDPOINT=https://&lt;api-id&gt;.execute-api.us-east-1.amazonaws.com
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <button onClick={closeModal} className="btn-primary">
                    Done
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

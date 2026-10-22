import React, { useState, useEffect } from 'react';
import { BookOpen, Shield, Layers, CheckCircle2, ChevronRight, Search, ShieldCheck } from 'lucide-react';
import { ApiClient } from '../api/client';

export const Rules = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('atomic'); // 'atomic' | 'correlation' | 'whitelist'
  const [search, setSearch] = useState('');

  useEffect(() => {
    const loadRules = async () => {
      try {
        const res = await ApiClient.getRules();
        setData(res);
      } catch (err) {
        console.error('Failed to load rules:', err);
      } finally {
        setLoading(false);
      }
    };
    loadRules();
  }, []);

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 400 }}>
        <div style={{ color: 'var(--text-muted)' }}>Loading detection rules and threat intelligence...</div>
      </div>
    );
  }

  const rules = data?.rules || [];
  const correlations = data?.correlations || [];
  const whitelist = data?.whitelist || {};

  const filteredRules = rules.filter((r) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      r.id?.toLowerCase().includes(q) ||
      r.name?.toLowerCase().includes(q) ||
      r.mitre_technique?.toLowerCase().includes(q) ||
      r.description?.toLowerCase().includes(q)
    );
  });

  return (
    <div style={{ maxWidth: 1440, margin: '0 auto', padding: '32px 24px' }}>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: '1.8rem', marginBottom: 6 }}>Detection Rules & Threat Intelligence</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Real-time heuristics, multi-stage correlation chains, and false-positive suppression policies.
        </p>
      </div>

      {/* Navigation Tabs & Search */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 16,
        marginBottom: 24,
      }}>
        {/* Tabs */}
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => setActiveTab('atomic')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '8px 16px',
              borderRadius: 'var(--radius-md)',
              fontSize: '0.88rem',
              fontWeight: 600,
              cursor: 'pointer',
              border: activeTab === 'atomic' ? '1px solid rgba(99, 102, 241, 0.4)' : '1px solid var(--border-subtle)',
              background: activeTab === 'atomic' ? 'rgba(99, 102, 241, 0.2)' : 'rgba(255, 255, 255, 0.03)',
              color: activeTab === 'atomic' ? '#ffffff' : 'var(--text-muted)',
              transition: 'all 0.15s ease',
            }}
          >
            <Shield size={16} />
            <span>Atomic Rules (BH001–BH008)</span>
          </button>

          <button
            onClick={() => setActiveTab('correlation')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '8px 16px',
              borderRadius: 'var(--radius-md)',
              fontSize: '0.88rem',
              fontWeight: 600,
              cursor: 'pointer',
              border: activeTab === 'correlation' ? '1px solid rgba(168, 85, 247, 0.4)' : '1px solid var(--border-subtle)',
              background: activeTab === 'correlation' ? 'rgba(168, 85, 247, 0.2)' : 'rgba(255, 255, 255, 0.03)',
              color: activeTab === 'correlation' ? '#ffffff' : 'var(--text-muted)',
              transition: 'all 0.15s ease',
            }}
          >
            <Layers size={16} />
            <span>Correlation Chains (CR01–CR03)</span>
          </button>

          <button
            onClick={() => setActiveTab('whitelist')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '8px 16px',
              borderRadius: 'var(--radius-md)',
              fontSize: '0.88rem',
              fontWeight: 600,
              cursor: 'pointer',
              border: activeTab === 'whitelist' ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid var(--border-subtle)',
              background: activeTab === 'whitelist' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.03)',
              color: activeTab === 'whitelist' ? '#ffffff' : 'var(--text-muted)',
              transition: 'all 0.15s ease',
            }}
          >
            <ShieldCheck size={16} />
            <span>Whitelist Policies</span>
          </button>
        </div>

        {activeTab === 'atomic' && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            background: 'rgba(0, 0, 0, 0.35)',
            border: '1px solid var(--border-card)',
            borderRadius: 'var(--radius-md)',
            padding: '6px 12px',
            minWidth: 260,
          }}>
            <Search size={15} style={{ color: 'var(--text-dim)' }} />
            <input
              type="text"
              placeholder="Filter rules..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                outline: 'none',
                color: '#ffffff',
                fontSize: '0.85rem',
                width: '100%',
              }}
            />
          </div>
        )}
      </div>

      {/* Tab 1: Atomic Rules */}
      {activeTab === 'atomic' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: 20 }}>
          {filteredRules.map((rule) => {
            const badgeClass =
              rule.severity === 'High' ? 'badge badge-high' :
              rule.severity === 'Medium' ? 'badge badge-medium' :
              'badge badge-low';

            return (
              <div key={rule.id} className="glass-panel" style={{ padding: 22, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        fontSize: '0.9rem',
                        color: 'var(--accent-cyan)',
                      }}>
                        {rule.id}
                      </span>
                      <span className={badgeClass}>{rule.severity}</span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className="badge-mitre">{rule.mitre_technique}</span>
                      <span style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.82rem',
                        fontWeight: 700,
                        color: '#fbbf24',
                      }}>
                        +{rule.base_score || rule.score} pts
                      </span>
                    </div>
                  </div>

                  <h3 style={{ fontSize: '1.05rem', marginBottom: 8 }}>
                    {rule.name}
                  </h3>

                  <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: 16 }}>
                    {rule.description}
                  </p>
                </div>

                <div style={{
                  background: 'rgba(0, 0, 0, 0.35)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  padding: '10px 12px',
                  fontSize: '0.75rem',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--text-dim)',
                }}>
                  <div style={{ marginBottom: 4 }}>
                    <strong style={{ color: 'var(--text-muted)' }}>Windows Event:</strong> Event ID {rule.event_id || 1} ({rule.event_type || 'ProcessCreate'})
                  </div>
                  <div>
                    <strong style={{ color: 'var(--text-muted)' }}>Trigger Condition:</strong> {rule.condition_summary || 'Pattern match on command line / target path'}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Tab 2: Correlation Rules */}
      {activeTab === 'correlation' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {correlations.map((cr) => (
            <div key={cr.id} className="glass-panel" style={{
              padding: 24,
              borderLeft: '4px solid #a855f7',
              background: 'radial-gradient(circle at top right, rgba(168, 85, 247, 0.08) 0%, rgba(17, 24, 39, 0.7) 60%)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12, flexWrap: 'wrap', gap: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 800,
                    fontSize: '1.1rem',
                    color: '#c084fc',
                  }}>
                    {cr.id}
                  </span>
                  <h3 style={{ fontSize: '1.15rem' }}>{cr.name}</h3>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{
                    fontSize: '0.78rem',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--text-dim)',
                    background: 'rgba(0, 0, 0, 0.3)',
                    padding: '4px 10px',
                    borderRadius: 6,
                  }}>
                    Sliding Window: {cr.time_window_seconds}s ({cr.time_window_seconds / 60}m)
                  </span>
                  <span style={{
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 800,
                    fontSize: '0.9rem',
                    color: '#f87171',
                    background: 'rgba(239, 68, 68, 0.15)',
                    padding: '4px 10px',
                    borderRadius: 6,
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                  }}>
                    +{cr.score_bonus} Bonus Risk
                  </span>
                </div>
              </div>

              <p style={{ fontSize: '0.9rem', color: '#e2e8f0', marginBottom: 16, lineHeight: 1.5 }}>
                {cr.explanation}
              </p>

              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-dim)' }}>
                  REQUIRED SEQUENCE:
                </span>
                {(cr.required_rules || []).map((step, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.82rem',
                      fontWeight: 700,
                      background: 'rgba(168, 85, 247, 0.2)',
                      color: '#d8b4fe',
                      padding: '4px 10px',
                      borderRadius: 6,
                      border: '1px solid rgba(168, 85, 247, 0.4)',
                    }}>
                      Step {idx + 1}: {step}
                    </span>
                    {idx < (cr.required_rules.length - 1) && (
                      <ChevronRight size={16} style={{ color: 'var(--text-dim)' }} />
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 3: Whitelist */}
      {activeTab === 'whitelist' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 24 }}>
          {/* Trusted Paths */}
          <div className="glass-panel" style={{ padding: 24 }}>
            <h3 style={{ fontSize: '1.1rem', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldCheck size={18} style={{ color: '#10b981' }} />
              Trusted Binary Paths
            </h3>
            <p style={{ color: 'var(--text-dim)', fontSize: '0.82rem', marginBottom: 16 }}>
              Processes executing strictly from these system paths bypass false positive triggers
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {(whitelist.trusted_paths || [
                'C:\\Windows\\System32\\*',
                'C:\\Program Files\\Google\\Chrome\\Application\\*',
                'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\*',
              ]).map((path, idx) => (
                <div key={idx} style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.82rem',
                  color: '#34d399',
                  background: 'rgba(16, 185, 129, 0.08)',
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid rgba(16, 185, 129, 0.2)',
                }}>
                  {path}
                </div>
              ))}
            </div>
          </div>

          {/* Trusted Publishers */}
          <div className="glass-panel" style={{ padding: 24 }}>
            <h3 style={{ fontSize: '1.1rem', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldCheck size={18} style={{ color: 'var(--accent-blue)' }} />
              Verified Code Publishers
            </h3>
            <p style={{ color: 'var(--text-dim)', fontSize: '0.82rem', marginBottom: 16 }}>
              Digitally signed binaries with valid Authenticode certificates
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {(whitelist.trusted_publishers || [
                'Microsoft Corporation',
                'Microsoft Windows',
                'Google LLC',
                'Mozilla Corporation',
              ]).map((pub, idx) => (
                <div key={idx} style={{
                  fontFamily: 'var(--font-sans)',
                  fontSize: '0.88rem',
                  fontWeight: 600,
                  color: '#93c5fd',
                  background: 'rgba(59, 130, 246, 0.08)',
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid rgba(59, 130, 246, 0.2)',
                }}>
                  {pub}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

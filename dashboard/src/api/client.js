/**
 * API Client for Dashboard
 * Communicates with AWS API Gateway HTTP API or provides rich demo data for local visualization.
 */

const getApiBase = () => {
  return import.meta.env.VITE_API_ENDPOINT || localStorage.getItem('api_endpoint') || '';
};

const getAuthHeaders = () => {
  const token = localStorage.getItem('auth_token') || 'demo-token';
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
  };
};

// Rich initial demo data for instant standalone SOC experience
const DEMO_STATS = {
  timestamp: new Date().toISOString(),
  total_alerts_24h: 7,
  severity_distribution: {
    High: 3,
    Medium: 3,
    Low: 1,
  },
  fleet_status: {
    total: 3,
    online: 2,
    offline: 1,
    revoked: 0,
  },
  top_rules: [
    { rule_id: 'BH001', count: 4 },
    { rule_id: 'BH002', count: 3 },
    { rule_id: 'CR01', count: 2 },
    { rule_id: 'BH004', count: 1 },
    { rule_id: 'BH007', count: 1 },
  ],
  recent_alerts: [
    {
      alert_id: 'a-101-demo',
      device_id: 'PC-LAB-01',
      timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
      rule_ids: ['BH001', 'CR01'],
      score: 70,
      severity: 'High',
      explanation: 'Correlated attack sequence: Browser policy modification (BH002) was followed by Chrome launch with custom proxy flag (--proxy-server=127.0.0.1:9999).',
      mitre_ids: ['T1090', 'T1112'],
      raw_event: {
        type: 'process_create',
        process_image: 'C:\\Users\\Student\\AppData\\Local\\Google\\Chrome\\chrome.exe',
        command_line: 'chrome.exe --proxy-server="127.0.0.1:9999"',
        parent_image: 'C:\\Users\\Student\\AppData\\Local\\Temp\\dropper.exe',
        user: 'LAB\\Student',
      },
    },
    {
      alert_id: 'a-102-demo',
      device_id: 'PC-LAB-01',
      timestamp: new Date(Date.now() - 45 * 60000).toISOString(),
      rule_ids: ['BH007'],
      score: 60,
      severity: 'High',
      explanation: 'Windows Security event log was cleared by user LAB\\Student. Defense evasion indicator.',
      mitre_ids: ['T1070.001'],
      raw_event: {
        type: 'log_cleared',
        user: 'LAB\\Student',
      },
    },
    {
      alert_id: 'a-103-demo',
      device_id: 'DESKTOP-OFFICE',
      timestamp: new Date(Date.now() - 120 * 60000).toISOString(),
      rule_ids: ['BH004'],
      score: 40,
      severity: 'Medium',
      explanation: 'Windows hosts file modified: C:\\Windows\\System32\\drivers\\etc\\hosts.',
      mitre_ids: ['T1565.001'],
      raw_event: {
        type: 'file_create',
        file_path: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
        process_image: 'C:\\Windows\\System32\\notepad.exe',
      },
    },
  ],
};

const DEMO_DEVICES = [
  {
    device_id: 'PC-LAB-01',
    status: 'Online',
    last_seen: new Date(Date.now() - 2 * 60000).toISOString(),
    agent_version: '1.0.0',
    uptime_seconds: 14420,
    os_version: 'Windows 11 Pro 23H2',
    hostname: 'DESKTOP-LAB-01',
    event_queue_size: 0,
  },
  {
    device_id: 'PC-LAB-02',
    status: 'Online',
    last_seen: new Date(Date.now() - 5 * 60000).toISOString(),
    agent_version: '1.0.0',
    uptime_seconds: 86400,
    os_version: 'Windows 10 Enterprise',
    hostname: 'DESKTOP-FINANCE-02',
    event_queue_size: 1,
  },
  {
    device_id: 'DESKTOP-OFFICE',
    status: 'Offline',
    last_seen: new Date(Date.now() - 25 * 60000).toISOString(),
    agent_version: '1.0.0',
    uptime_seconds: 3600,
    os_version: 'Windows 11 Pro',
    hostname: 'OFFICE-RECEPTION',
    event_queue_size: 0,
  },
];

const DEMO_RULES = [
  {
    id: 'BH001',
    name: 'Browser launched with extension/proxy flags',
    description: 'Detects browser processes launched with suspicious command-line flags',
    event_type: ['process_create'],
    base_score: 40,
    mitre_ids: ['T1090', 'T1176'],
    explanation_template: 'Browser {process_image} was launched with suspicious flag(s) in command line: "{command_line}".',
  },
  {
    id: 'BH002',
    name: 'Browser policy registry modified',
    description: 'Detects changes to Chrome/Edge policy registry keys',
    event_type: ['registry_set'],
    base_score: 50,
    mitre_ids: ['T1112'],
    explanation_template: 'Browser policy registry key modified: {registry_key}\\{registry_value_name} set to "{registry_value}".',
  },
  {
    id: 'BH003',
    name: 'System proxy / PAC script changed',
    description: 'Detects changes to system-wide proxy or auto-config URL',
    event_type: ['registry_set'],
    base_score: 30,
    mitre_ids: ['T1090'],
    explanation_template: 'System proxy setting changed: {registry_value_name} set to "{registry_value}".',
  },
  {
    id: 'BH004',
    name: 'Hosts file modified',
    description: 'Detects modifications to the Windows hosts file',
    event_type: ['file_create'],
    base_score: 40,
    mitre_ids: ['T1565.001'],
    explanation_template: 'Windows hosts file was modified: {file_path}.',
  },
  {
    id: 'BH005',
    name: 'Browser shortcut modified',
    description: 'Detects changes to browser .lnk shortcut files',
    event_type: ['file_create'],
    base_score: 30,
    mitre_ids: ['T1547.009'],
    explanation_template: 'Browser shortcut file was modified: {file_path}.',
  },
  {
    id: 'BH006',
    name: 'Suspicious scheduled task or service',
    description: 'Detects creation of scheduled tasks or services relating to hijacking',
    event_type: ['task_create', 'service_install'],
    base_score: 35,
    mitre_ids: ['T1053.005', 'T1543.003'],
    explanation_template: 'Scheduled task/service created with browser keywords: "{command_line}".',
  },
  {
    id: 'BH007',
    name: 'Security log cleared',
    description: 'Detects clearing of the Windows Security event log (defense evasion)',
    event_type: ['log_cleared'],
    base_score: 60,
    mitre_ids: ['T1070.001'],
    explanation_template: 'Windows Security event log was cleared by user {user}.',
  },
  {
    id: 'BH008',
    name: 'Root certificate added',
    description: 'Detects addition of root certificates to the trusted store',
    event_type: ['registry_set'],
    base_score: 45,
    mitre_ids: ['T1553.004'],
    explanation_template: 'A root certificate was added to the trusted certificate store: {registry_key}.',
  },
];

export const apiClient = {
  async getStats() {
    const base = getApiBase();
    if (!base) return DEMO_STATS;
    try {
      const res = await fetch(`${base}/stats`, { headers: getAuthHeaders() });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('API /stats fetch error, using fallback:', e);
    }
    return DEMO_STATS;
  },

  async getAlerts(params = {}) {
    const base = getApiBase();
    if (!base) {
      let filtered = [...DEMO_STATS.recent_alerts];
      if (params.device) filtered = filtered.filter(a => a.device_id === params.device);
      if (params.severity) filtered = filtered.filter(a => a.severity.toLowerCase() === params.severity.toLowerCase());
      return { count: filtered.length, alerts: filtered };
    }
    try {
      const q = new URLSearchParams(params).toString();
      const res = await fetch(`${base}/alerts?${q}`, { headers: getAuthHeaders() });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('API /alerts fetch error:', e);
    }
    return { count: DEMO_STATS.recent_alerts.length, alerts: DEMO_STATS.recent_alerts };
  },

  async getAlert(alertId) {
    const base = getApiBase();
    if (!base) {
      const alert = DEMO_STATS.recent_alerts.find(a => a.alert_id === alertId) || DEMO_STATS.recent_alerts[0];
      const timeline = [
        { timestamp: new Date(Date.now() - 17 * 60000).toISOString(), type: 'registry_set', process_image: 'evil.exe', registry_key: 'HKLM\\SOFTWARE\\Policies\\Google\\Chrome' },
        { timestamp: new Date(Date.now() - 15 * 60000).toISOString(), type: 'process_create', process_image: 'chrome.exe', command_line: '--proxy-server=127.0.0.1:9999' },
      ];
      return { alert, timeline };
    }
    try {
      const res = await fetch(`${base}/alerts/${alertId}`, { headers: getAuthHeaders() });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('API /alerts/:id fetch error:', e);
    }
    return { alert: DEMO_STATS.recent_alerts[0], timeline: [] };
  },

  async getDevices() {
    const base = getApiBase();
    if (!base) return { count: DEMO_DEVICES.length, devices: DEMO_DEVICES };
    try {
      const res = await fetch(`${base}/devices`, { headers: getAuthHeaders() });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('API /devices fetch error:', e);
    }
    return { count: DEMO_DEVICES.length, devices: DEMO_DEVICES };
  },

  async registerDevice(payload) {
    const base = getApiBase();
    if (!base) {
      const simulatedKey = Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
      const newDev = {
        device_id: payload.device_id,
        status: 'Online',
        last_seen: new Date().toISOString(),
        agent_version: '1.0.0',
        uptime_seconds: 0,
        os_version: 'Windows 11',
        hostname: payload.hostname || payload.device_id,
        event_queue_size: 0,
      };
      DEMO_DEVICES.push(newDev);
      return {
        device_id: payload.device_id,
        api_key: simulatedKey,
        status: 'Online',
        message: 'Store this API key securely. It cannot be retrieved again.',
      };
    }
    const res = await fetch(`${base}/devices`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
    });
    return await res.json();
  },

  async revokeDeviceKey(deviceId) {
    const base = getApiBase();
    if (!base) {
      const dev = DEMO_DEVICES.find(d => d.device_id === deviceId);
      if (dev) dev.status = 'Revoked';
      return { status: 'Revoked', device_id: deviceId };
    }
    const res = await fetch(`${base}/devices/${deviceId}/key`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    return await res.json();
  },

  async getRules() {
    const base = getApiBase();
    if (!base) {
      return {
        rules: DEMO_RULES,
        correlations: [
          {
            id: 'CR01',
            name: 'Registry policy change followed by browser launch',
            required_rules: ['BH002', 'BH001'],
            time_window_seconds: 300,
            score_bonus: 30,
            explanation: 'Browser policy registry modification (BH002) was followed by browser execution with custom flags within 5 minutes (+30 correlation risk).',
          },
          {
            id: 'CR02',
            name: 'Proxy redirection and hosts file tampering',
            required_rules: ['BH003', 'BH004'],
            time_window_seconds: 600,
            score_bonus: 25,
            explanation: 'Proxy setting tampering (BH003) combined with Windows hosts file alteration (BH004) detected within 10 minutes (+25 correlation risk).',
          },
          {
            id: 'CR03',
            name: 'Detection followed by security log clearing',
            required_rules: ['BH*', 'BH007'],
            time_window_seconds: 600,
            score_bonus: 30,
            explanation: 'Attack activity detected followed immediately by Windows Security log clearing (+30 defense evasion penalty).',
          },
        ],
        whitelist: {
          trusted_paths: ['C:\\Windows\\System32\\*', 'C:\\Program Files\\Google\\*'],
          trusted_publishers: ['Microsoft Corporation', 'Google LLC'],
        },
      };
    }
    try {
      const res = await fetch(`${base}/rules`, { headers: getAuthHeaders() });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('API /rules fetch error:', e);
    }
    return { rules: DEMO_RULES, correlations: [], whitelist: {} };
  },

  async getAlertDetail(alertId) {
    const data = await this.getAlert(alertId);
    if (data.alert) {
      return {
        ...data.alert,
        timeline: (data.timeline || []).map(t => ({
          timestamp: t.timestamp,
          title: t.process_image || t.registry_key || t.file_path || 'Forensic Event',
          description: t.command_line || t.target_object || (t.type + ' recorded by Sysmon/Security log'),
          is_trigger: t.process_image?.includes('chrome') || false,
        })),
      };
    }
    return data;
  },

  async createDevice(payload) {
    const deviceId = payload.device_id || `PC-${(payload.hostname || 'WIN').replace(/[^a-zA-Z0-9]/g, '').substring(0, 8).toUpperCase()}-${Math.floor(100 + Math.random() * 900)}`;
    return await this.registerDevice({
      ...payload,
      device_id: deviceId,
    });
  },
};

export const ApiClient = apiClient;
export default apiClient;

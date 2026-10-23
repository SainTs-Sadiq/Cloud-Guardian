import { useState, useEffect, useCallback, useRef } from "react";
import {
  LineChart, Line, AreaChart, Area,
  XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from "recharts";

// Deployment-configurable: runtime override (window.CG_API_URL) wins,
// then build-time VITE_API_URL, then localhost for dev.
const API_BASE = (typeof window !== "undefined" && window.CG_API_URL)
  || (import.meta.env && import.meta.env.VITE_API_URL)
  || "http://localhost:8000";
const POLL_INTERVAL_MS = 30_000;

const C = {
  bg: "#0b0f1a", sidebar: "#0d1117", card: "#111827",
  cardBorder: "#1e2a3a", hover: "#161f2e",
  accent: "#3b82f6", green: "#22c55e", red: "#ef4444",
  orange: "#f97316", yellow: "#eab308", purple: "#a855f7",
  text: "#f1f5f9", muted: "#94a3b8", dim: "#475569",
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
};
const SEV_COLOR = { critical: C.critical, high: C.high, medium: C.medium, low: C.low };
const SEV_LABEL = { critical: "Critical", high: "High", medium: "medium", low: "Low" };

let _token = null;
const getToken = () => _token;
const setToken = (t) => { _token = t; };

async function api(path, opts = {}) {
  const token = getToken();
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401) throw Object.assign(new Error("Unauthorized"), { status: 401 });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `API error ${res.status}`);
  }
  return res.json();
}

function useApi(path, deps = [], options = {}) {
  const { skip = false, interval = null } = options;
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(!skip);
  const [error, setError] = useState(null);

  const fetch_ = useCallback(async () => {
    if (skip) return;
    try {
      setLoading(true);
      const d = await api(path);
      setData(d);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [path, skip, ...deps]);

  useEffect(() => { fetch_(); }, [fetch_]);

  useEffect(() => {
    if (!interval) return;
    const t = setInterval(fetch_, interval);
    return () => clearInterval(t);
  }, [fetch_, interval]);

  return { data, loading, error, refetch: fetch_ };
}

function timeAgo(iso) {
  if (!iso) return "—";
  const diff = (Date.now() - new Date(iso)) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}

function fmtDate(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

function deriveStats(alerts, coverage, health) {
  const all = alerts?.alerts || [];
  const active = all.filter(a => !["remediated","false_positive","suppressed"].includes(a.status));
  const critical = active.filter(a => a.risk_tier === "critical");
  const pending = all.filter(a => a.status === "pending_approval").length;
  const remediated = all.filter(a => a.status === "remediated").length;
  const total = all.length;
  const successRate = total > 0 ? Math.round((remediated / total) * 100) : 0;

  const deduction = Math.min(40,
    critical.length * 8 +
    active.filter(a => a.risk_tier === "high").length * 3 +
    active.filter(a => a.risk_tier === "medium").length * 1
  );
  const secScore = Math.max(0, 100 - deduction);

  return {
    secScore,
    activeThreats: active.length,
    criticalCount: critical.length,
    connectedAccounts: health?.guardduty_enabled !== undefined ? "—" : "—",
    successRate,
    pending,
    remediated,
    total,
  };
}

function deriveThreatActivity(alerts) {
  const all = alerts?.alerts || [];
  const now = Date.now();
  const days = Array.from({ length: 7 }, (_, i) => {
    const d = new Date(now - (6 - i) * 86400000);
    return { date: d.toLocaleDateString("en-US", { month: "short", day: "numeric" }), ts: d };
  });

  return days.map(({ date, ts }) => {
    const next = new Date(ts.getTime() + 86400000);
    const dayAlerts = all.filter(a => {
      const t = new Date(a.event_time);
      return t >= ts && t < next;
    });
    return {
      date,
      critical: dayAlerts.filter(a => a.risk_tier === "critical").length,
      high: dayAlerts.filter(a => a.risk_tier === "high").length,
      medium: dayAlerts.filter(a => a.risk_tier === "medium").length,
      low: dayAlerts.filter(a => a.risk_tier === "low").length,
    };
  });
}

function deriveTopServices(alerts) {
  const all = alerts?.alerts || [];
  const counts = {};
  all.forEach(a => {
    const svc = guessService(a.event_name || "");
    counts[svc] = (counts[svc] || 0) + 1;
  });
  const COLORS = ["#3b82f6", "#22c55e", "#f97316", "#a855f7", "#475569"];
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const total = sorted.reduce((s, [, v]) => s + v, 0) || 1;
  return sorted.map(([name, count], i) => ({
    name, value: Math.round((count / total) * 100), color: COLORS[i] || C.dim,
  }));
}

function guessService(eventName) {
  const e = eventName.toLowerCase();
  if (e.includes("bucket") || e.includes("s3") || e.includes("object")) return "S3";
  if (e.includes("instance") || e.includes("ec2") || e.includes("security")) return "EC2";
  if (e.includes("function") || e.includes("lambda")) return "Lambda";
  if (e.includes("secret") || e.includes("parameter")) return "Secrets";
  return "IAM";
}

function deriveRemediationDonut(stats) {
  const { remediated, pending, total } = stats;
  const failed = Math.max(0, total - remediated - pending - (total - remediated - pending));
  return [
    { name: "Successful", value: remediated, color: C.green },
    { name: "Pending",    value: pending,    color: C.yellow },
    { name: "Failed",     value: Math.max(0, total - remediated - pending), color: C.red },
  ];
}

function deriveSecScoreTrend(alerts) {
  const all = alerts?.alerts || [];
  return Array.from({ length: 7 }, (_, i) => {
    const d = new Date(Date.now() - (6 - i) * 86400000);
    return {
      date: d.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
      score: Math.max(40, Math.min(100, 80 - all.filter(a =>
        new Date(a.event_time) <= d && a.risk_tier === "critical"
      ).length * 4)),
    };
  });
}

function deriveCoverage(coverage) {
  const tactics = coverage?.tactics || [];
  const total = coverage?.total_techniques_mapped || 35;
  const mapped = tactics.reduce((s, t) => s + t.technique_count, 0);
  return [
    { name: "CIS AWS Foundations", pct: Math.min(100, Math.round((mapped / total) * 90) + 10), color: C.green },
    { name: "MITRE ATT&CK Cloud",  pct: Math.min(100, Math.round((total / 40) * 100)),          color: C.green },
    { name: "SOC 2 Type II",       pct: coverage?.active_alert_count === 0 ? 95 : 75,           color: C.yellow },
    { name: "ISO 27001",           pct: Math.min(100, Math.round((mapped / total) * 80) + 5),   color: C.yellow },
  ];
}

const Spinner = ({ size = 16 }) => (
  <div style={{
    width: size, height: size, border: `2px solid ${C.cardBorder}`,
    borderTop: `2px solid ${C.accent}`, borderRadius: "50%",
    animation: "spin 0.8s linear infinite", display: "inline-block",
  }}/>
);

const Badge = ({ sev, small }) => {
  const label = SEV_LABEL[sev?.toLowerCase()] || sev || "—";
  const col = SEV_COLOR[sev?.toLowerCase()] || C.muted;
  return (
    <span style={{
      display: "inline-block", padding: small ? "2px 7px" : "3px 9px",
      borderRadius: 4, fontSize: small ? 10 : 11, fontWeight: 700,
      background: `${col}22`, color: col, border: `1px solid ${col}44`,
    }}>{label}</span>
  );
};

const StatusBadge = ({ status }) => {
  const map = {
    pending_approval: { bg: "#3b82f622", c: "#60a5fa", border: "#3b82f644", label: "Pending" },
    detected:         { bg: "#f9731622", c: "#fb923c", border: "#f9731644", label: "Detected" },
    remediated:       { bg: "#22c55e22", c: "#4ade80", border: "#22c55e44", label: "Resolved" },
    remediation_failed:{ bg:"#ef444422", c: "#f87171", border: "#ef444444", label: "Failed" },
    false_positive:   { bg: "#47556922", c: "#94a3b8", border: "#47556944", label: "Dismissed" },
    notified:         { bg: "#a855f722", c: "#c084fc", border: "#a855f744", label: "Notified" },
  };
  const s = map[status] || { bg: "#3b82f622", c: "#60a5fa", border: "#3b82f644", label: status };
  return (
    <span style={{
      display: "inline-block", padding: "3px 9px", borderRadius: 4,
      fontSize: 11, fontWeight: 600, background: s.bg, color: s.c, border: `1px solid ${s.border}`,
    }}>{s.label}</span>
  );
};

const MiniSparkline = ({ data, color, height = 36 }) => (
  <ResponsiveContainer width="100%" height={height}>
    <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
      <defs>
        <linearGradient id={`sg-${color.replace("#", "")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="5%"  stopColor={color} stopOpacity={0.3}/>
          <stop offset="95%" stopColor={color} stopOpacity={0}/>
        </linearGradient>
      </defs>
      <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.5}
        fill={`url(#sg-${color.replace("#", "")})`} dot={false}/>
    </AreaChart>
  </ResponsiveContainer>
);

const ErrorBanner = ({ message, onRetry }) => (
  <div style={{
    background: "#ef444411", border: `1px solid #ef444433`, borderRadius: 8,
    padding: "10px 14px", fontSize: 12, color: C.red,
    display: "flex", justifyContent: "space-between", alignItems: "center",
  }}>
    <span>⚠ {message}</span>
    {onRetry && <button onClick={onRetry} style={{
      background: "transparent", border: `1px solid ${C.red}`, color: C.red,
      borderRadius: 4, padding: "3px 8px", fontSize: 11, cursor: "pointer",
    }}>Retry</button>}
  </div>
);

const ChartTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: "#1e2a3a", border: `1px solid ${C.cardBorder}`,
      borderRadius: 8, padding: "10px 14px", fontSize: 12,
    }}>
      <div style={{ color: C.muted, marginBottom: 6 }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ color: p.color, display: "flex", gap: 8, marginBottom: 2 }}>
          <span>{p.name}:</span><strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
};

function LoginScreen({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [mode, setMode] = useState("login");
  const [orgName, setOrgName] = useState("");
  const [orgSlug, setOrgSlug] = useState("");

  async function handleSubmit() {
    setLoading(true); setError(null);
    try {
      if (mode === "register") {
        const res = await api("/auth/register", {
          method: "POST",
          body: { org_name: orgName, org_slug: orgSlug, email, full_name: "Admin", password },
        });
        setToken(res.access_token);
        onLogin(res);
      } else {
        const res = await api("/auth/login", {
          method: "POST",
          body: { email, password },
        });
        setToken(res.access_token);
        onLogin(res);
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  const inp = {
    width: "100%", padding: "10px 12px", borderRadius: 8, fontSize: 13,
    background: C.hover, border: `1px solid ${C.cardBorder}`, color: C.text,
    outline: "none", boxSizing: "border-box",
  };

  return (
    <div style={{
      minHeight: "100vh", background: C.bg, display: "flex",
      alignItems: "center", justifyContent: "center",
      fontFamily: "'Inter', -apple-system, sans-serif",
    }}>
      <div style={{
        width: 380, background: C.card, border: `1px solid ${C.cardBorder}`,
        borderRadius: 16, padding: "36px 32px",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 28 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: "linear-gradient(135deg,#3b82f6,#8b5cf6)",
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18,
          }}>⬡</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Cloud Guardian</div>
            <div style={{ fontSize: 11, color: C.muted }}>Security Operations Platform</div>
          </div>
        </div>

        <div style={{ fontSize: 18, fontWeight: 700, color: C.text, marginBottom: 20 }}>
          {mode === "login" ? "Sign in" : "Create account"}
        </div>

        {error && <ErrorBanner message={error}/>}

        <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: error ? 12 : 0 }}>
          {mode === "register" && <>
            <input placeholder="Organization name" value={orgName}
              onChange={e => setOrgName(e.target.value)} style={inp}/>
            <input placeholder="Org slug (e.g. acme-corp)" value={orgSlug}
              onChange={e => setOrgSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
              style={inp}/>
          </>}
          <input placeholder="Email address" type="email" value={email}
            onChange={e => setEmail(e.target.value)} style={inp}/>
          <input placeholder="Password" type="password" value={password}
            onChange={e => setPassword(e.target.value)} style={inp}
            onKeyDown={e => e.key === "Enter" && handleSubmit()}/>

          <button onClick={handleSubmit} disabled={loading} style={{
            width: "100%", padding: "11px", borderRadius: 8, border: "none",
            background: C.accent, color: "#fff", fontSize: 13, fontWeight: 600,
            cursor: loading ? "not-allowed" : "pointer", opacity: loading ? 0.7 : 1,
            display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
          }}>
            {loading && <Spinner size={14}/>}
            {mode === "login" ? "Sign in" : "Create account"}
          </button>
        </div>

        <div style={{ textAlign: "center", marginTop: 16, fontSize: 12, color: C.muted }}>
          {mode === "login" ? "Don't have an account? " : "Already have an account? "}
          <span style={{ color: C.accent, cursor: "pointer" }}
            onClick={() => { setMode(mode === "login" ? "register" : "login"); setError(null); }}>
            {mode === "login" ? "Register" : "Sign in"}
          </span>
        </div>

        <div style={{
          marginTop: 20, padding: "10px 12px", borderRadius: 8,
          background: "#1e2a3a", fontSize: 11, color: C.muted,
        }}>
          <strong style={{ color: C.text }}>Local dev:</strong> make sure{" "}
          <code style={{ color: C.accent }}>uvicorn api.app:app --port 8000</code> is running.
        </div>
      </div>
    </div>
  );
}

const StatCard = ({ icon, iconBg, label, value, sub, sparkData, sparkColor, loading }) => (
  <div style={{
    background: C.card, border: `1px solid ${C.cardBorder}`,
    borderRadius: 12, padding: "16px 18px",
  }}>
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
      <div style={{
        width: 30, height: 30, borderRadius: 8, background: iconBg,
        display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14,
      }}>{icon}</div>
      <span style={{ fontSize: 12, color: C.muted, fontWeight: 500 }}>{label}</span>
    </div>
    {loading ? (
      <div style={{ display: "flex", alignItems: "center", gap: 8, height: 32 }}>
        <Spinner size={18}/>
        <span style={{ color: C.dim, fontSize: 12 }}>Loading…</span>
      </div>
    ) : (
      <>
        <div style={{ fontSize: 28, fontWeight: 700, color: C.text, lineHeight: 1 }}>{value}</div>
        {sub && <div style={{ fontSize: 11, marginTop: 5 }}>{sub}</div>}
        {sparkData?.length > 0 && (
          <div style={{ marginTop: 6 }}>
            <MiniSparkline data={sparkData} color={sparkColor || C.accent} height={34}/>
          </div>
        )}
      </>
    )}
  </div>
);

const NAV = [
  ["⊞", "Overview"], ["⚡", "Incidents"], ["📅", "Threat Timeline"],
  ["🏗️", "Infrastructure"], ["🔧", "Remediation"], ["📊", "Analytics"],
  ["✅", "Compliance"], ["📄", "Reports"], ["🧪", "Attack Simulator"], ["🔔", "Alerts"],
  ["👥", "Team"], ["💳", "Billing"], ["🧠", "Learning"], ["⚙️", "Settings"],
];
const CONFIG_NAV = [
  ["☁️", "AWS Accounts"], ["🔗", "Integrations"],
  ["🛡️", "Detection Policies"], ["📣", "Notification Channels"], ["🔑", "API Keys"],
];

function Dashboard({ onLogout }) {
  const [activeNav, setActiveNav] = useState("Overview");
  const [approvingId, setApprovingId] = useState(null);
  const [approveMsg, setApproveMsg] = useState({});
  const [scanLoading, setScanLoading] = useState(false);
  const [scanMsg, setScanMsg] = useState(null);
  const [me, setMe] = useState(null);

  const { data: health, loading: healthLoading, refetch: refetchHealth } =
    useApi("/health", [], { interval: POLL_INTERVAL_MS });

  const { data: alerts, loading: alertsLoading, error: alertsError, refetch: refetchAlerts } =
    useApi("/alerts?limit=500", [], { interval: POLL_INTERVAL_MS });

  const { data: coverage, loading: coverageLoading, refetch: refetchCoverage } =
    useApi("/coverage", [], { interval: POLL_INTERVAL_MS });

  const { data: pending, loading: pendingLoading, refetch: refetchPending } =
    useApi("/remediation/pending", [], { interval: POLL_INTERVAL_MS });

  const { data: accounts, refetch: refetchAccounts } = useApi("/accounts", []);

  useEffect(() => {
    api("/users/me").then(setMe).catch(() => {});
  }, []);

  const stats = deriveStats(alerts, coverage, health);
  const threatActivity = deriveThreatActivity(alerts);
  const topServices = deriveTopServices(alerts);
  const remDonut = deriveRemediationDonut(stats);
  const scoreTrend = deriveSecScoreTrend(alerts);
  const complianceData = deriveCoverage(coverage);

  const allAlerts = alerts?.alerts || [];
  const recentAlerts = [...allAlerts]
    .sort((a, b) => new Date(b.event_time) - new Date(a.event_time))
    .slice(0, 5);
  const criticalAlerts = allAlerts.filter(a => a.risk_tier === "critical").slice(0, 5);
  const pendingList = pending?.alerts || [];

  const sparkScore = scoreTrend.map(d => ({ v: d.score }));
  const sparkThreats = threatActivity.map(d => ({ v: d.critical + d.high }));
  const sparkCritical = threatActivity.map(d => ({ v: d.critical }));

  async function handleApprove(eventId) {
    setApprovingId(eventId);
    try {
      await api(`/remediation/${eventId}/approve`, {
        method: "POST", body: { confirmed: true },
      });
      setApproveMsg(m => ({ ...m, [eventId]: { ok: true, text: "Remediation executed." } }));
      refetchPending(); refetchAlerts();
    } catch (e) {
      setApproveMsg(m => ({ ...m, [eventId]: { ok: false, text: e.message } }));
    } finally {
      setApprovingId(null);
    }
  }

  async function handleDismiss(eventId) {
    try {
      await api(`/remediation/${eventId}/dismiss`, {
        method: "POST", body: { reason: "Dismissed from dashboard" },
      });
      refetchPending(); refetchAlerts();
    } catch {}
  }

  async function handleScan() {
    setScanLoading(true); setScanMsg(null);
    try {
      const res = await api("/scan", { method: "POST", body: { minutes: 15, use_ml: true } });
      setScanMsg({ ok: true, text: res.message });
      setTimeout(() => { refetchAlerts(); refetchCoverage(); refetchPending(); }, 3000);
    } catch (e) {
      setScanMsg({ ok: false, text: e.message });
    } finally {
      setScanLoading(false);
    }
  }

  const loading = alertsLoading || healthLoading;

  const tacticIcon = t => ({
    "Initial Access": "🚪", "Execution": "⚙️", "Persistence": "📌",
    "Privilege Escalation": "⬆️", "Defense Evasion": "🛡️", "Credential Access": "🔑",
    "Discovery": "🔍", "Lateral Movement": "↔️", "Collection": "📦",
    "Exfiltration": "📤", "Impact": "💥",
  }[t] || "⚡");

  return (
    <div style={{
      display: "flex", minHeight: "100vh", background: C.bg,
      fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
      color: C.text, fontSize: 13,
    }}>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: ${C.sidebar}; }
        ::-webkit-scrollbar-thumb { background: ${C.cardBorder}; border-radius: 2px; }
        button { font-family: inherit; }
        input { font-family: inherit; }
        select { font-family: inherit; }
      `}</style>

      {/* ── Sidebar ── */}
      <aside style={{
        width: 220, flexShrink: 0, background: C.sidebar,
        borderRight: `1px solid ${C.cardBorder}`,
        display: "flex", flexDirection: "column",
        position: "sticky", top: 0, height: "100vh", overflowY: "auto",
      }}>
        <div style={{ padding: "20px 16px 16px", borderBottom: `1px solid ${C.cardBorder}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: 8,
              background: "linear-gradient(135deg,#3b82f6,#8b5cf6)",
              display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16,
            }}>⬡</div>
            <span style={{ fontSize: 15, fontWeight: 700 }}>Cloud Guardian</span>
          </div>
        </div>

        <nav style={{ padding: "12px 8px", flex: 1 }}>
          {NAV.map(([icon, label]) => (
            <button key={label} onClick={() => setActiveNav(label)} style={{
              display: "flex", alignItems: "center", gap: 10, width: "100%",
              padding: "8px 10px", borderRadius: 8, border: "none", cursor: "pointer",
              background: activeNav === label ? `${C.accent}22` : "transparent",
              color: activeNav === label ? C.accent : C.muted,
              fontWeight: activeNav === label ? 600 : 400,
              fontSize: 13, textAlign: "left", marginBottom: 2, transition: "all 0.15s",
            }}>
              <span>{icon}</span>{label}
              {label === "Remediation" && pendingList.length > 0 && (
                <span style={{
                  marginLeft: "auto", background: C.red, color: "#fff",
                  borderRadius: 10, padding: "1px 6px", fontSize: 10, fontWeight: 700,
                }}>{pendingList.length}</span>
              )}
            </button>
          ))}

          <div style={{ padding: "12px 10px 6px", marginTop: 8 }}>
            <span style={{ fontSize: 10, fontWeight: 600, color: C.dim, letterSpacing: "0.08em" }}>
              CONFIGURATION
            </span>
          </div>
          {CONFIG_NAV.map(([icon, label]) => (
            <button key={label} onClick={() => setActiveNav(label)} style={{
              display: "flex", alignItems: "center", gap: 10, width: "100%",
              padding: "8px 10px", borderRadius: 8, border: "none", cursor: "pointer",
              background: activeNav === label ? `${C.accent}22` : "transparent",
              color: activeNav === label ? C.accent : C.muted,
              fontWeight: activeNav === label ? 600 : 400,
              fontSize: 13, textAlign: "left", marginBottom: 2, transition: "all 0.15s",
            }}>
              <span>{icon}</span>{label}
            </button>
          ))}
        </nav>

        {/* Upgrade card */}
        <div style={{
          margin: "0 12px 12px", padding: 14, borderRadius: 10,
          background: "linear-gradient(135deg,#1e3a5f,#1e2a4a)",
          border: `1px solid #2a4a7a`, textAlign: "center",
        }}>
          <div style={{ fontSize: 22, marginBottom: 6 }}>⬡</div>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>Upgrade Your Plan</div>
          <div style={{ fontSize: 11, color: C.muted, marginBottom: 10, lineHeight: 1.4 }}>
            Unlock advanced features and enhance your security posture.
          </div>
          <button style={{
            width: "100%", padding: 7, borderRadius: 6, border: "none",
            background: C.accent, color: "#fff", fontSize: 11, fontWeight: 600, cursor: "pointer",
          }}>Upgrade Now</button>
        </div>

        <button onClick={onLogout} style={{
          margin: "0 12px 12px", padding: "8px", borderRadius: 8,
          border: `1px solid ${C.cardBorder}`, background: "transparent",
          color: C.muted, fontSize: 12, cursor: "pointer",
        }}>Sign out</button>

        <div style={{ padding: "8px 16px", fontSize: 10, color: C.dim }}>
          © 2025 Cloud Guardian
        </div>
      </aside>

      {/* ── Main ── */}
      <main style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>

        {/* Topbar */}
        <header style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "14px 24px", borderBottom: `1px solid ${C.cardBorder}`,
          background: C.sidebar, position: "sticky", top: 0, zIndex: 10,
        }}>
          <div>
            <div style={{ fontSize: 20, fontWeight: 700 }}>{activeNav}</div>
            <div style={{ fontSize: 12, color: C.muted, marginTop: 2 }}>
              {me ? `Welcome back, ${me.full_name}! ` : ""}
              {health?.status === "healthy"
                ? "All systems operational."
                : health?.status === "no_credentials"
                  ? "⚠ AWS credentials not configured."
                  : "⚠ Some services degraded."}
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {/* Account count */}
            <div style={{
              display: "flex", alignItems: "center", gap: 7, padding: "7px 12px",
              background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 8, fontSize: 12,
            }}>
              <span style={{
                background: "#ff9900", borderRadius: 4,
                padding: "2px 5px", fontSize: 10, fontWeight: 700, color: "#000",
              }}>AWS</span>
              <span>{accounts ? `${accounts.length} Account${accounts.length !== 1 ? "s" : ""}` : "…"}</span>
            </div>

            {/* Scan button */}
            <button onClick={handleScan} disabled={scanLoading} style={{
              display: "flex", alignItems: "center", gap: 6, padding: "7px 14px",
              background: C.accent, border: "none", borderRadius: 8,
              color: "#fff", fontSize: 12, fontWeight: 600, cursor: scanLoading ? "not-allowed" : "pointer",
              opacity: scanLoading ? 0.7 : 1,
            }}>
              {scanLoading ? <Spinner size={12}/> : "🔍"} Scan Now
            </button>

            {/* Health indicator */}
            <div style={{
              width: 36, height: 36, borderRadius: 8,
              background: C.card, border: `1px solid ${C.cardBorder}`,
              display: "flex", alignItems: "center", justifyContent: "center",
              position: "relative", cursor: "default",
            }}>
              🔔
              {pendingList.length > 0 && (
                <span style={{
                  position: "absolute", top: 6, right: 6, width: 8, height: 8,
                  borderRadius: "50%", background: C.red, border: `2px solid ${C.sidebar}`,
                }}/>
              )}
            </div>

            {/* Avatar */}
            {me && (
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{
                  width: 34, height: 34, borderRadius: "50%",
                  background: "linear-gradient(135deg,#3b82f6,#8b5cf6)",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 14, fontWeight: 700,
                }}>{me.full_name?.[0] || "U"}</div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600 }}>{me.full_name}</div>
                  <div style={{ fontSize: 10, color: C.muted, textTransform: "capitalize" }}>{me.role}</div>
                </div>
              </div>
            )}
          </div>
        </header>

        {/* Scan message */}
        {scanMsg && (
          <div style={{
            padding: "10px 24px",
            background: scanMsg.ok ? "#22c55e11" : "#ef444411",
            borderBottom: `1px solid ${scanMsg.ok ? "#22c55e33" : "#ef444433"}`,
            fontSize: 12,
            color: scanMsg.ok ? C.green : C.red,
          }}>
            {scanMsg.ok ? "✓" : "⚠"} {scanMsg.text}
          </div>
        )}

        <div style={{ padding: "24px", flex: 1, overflowY: "auto" }}>

          {/* ── Overview page ── */}
          {activeNav === "Overview" && (
            <>
              {/* ── Row 1: 6 stat cards ── */}
              <div style={{ display:"grid", gridTemplateColumns:"repeat(6,1fr)", gap:14, marginBottom:20 }}>

                {/* Security Score */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"16px 18px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:10 }}>
                    <div style={{ width:30, height:30, borderRadius:8, background:"#22c55e22", display:"flex", alignItems:"center", justifyContent:"center", fontSize:14 }}>🛡️</div>
                    <span style={{ fontSize:11, color:C.muted, fontWeight:500 }}>Security Score</span>
                    <span style={{ marginLeft:"auto", fontSize:10, color:C.dim }}>ⓘ</span>
                  </div>
                  {loading ? <Spinner size={18}/> : <>
                    <div style={{ fontSize:28, fontWeight:700, lineHeight:1 }}>
                      {stats.secScore}<span style={{ fontSize:14, color:C.muted }}> / 100</span>
                    </div>
                    <div style={{ fontSize:11, color:C.green, fontWeight:600, marginTop:5 }}>
                      ● {stats.secScore>=80?"Good":stats.secScore>=60?"Fair":"Poor"}
                    </div>
                    <MiniSparkline data={sparkScore} color={C.green} height={36}/>
                  </>}
                </div>

                {/* Active Threats */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"16px 18px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:10 }}>
                    <div style={{ width:30, height:30, borderRadius:8, background:"#ef444422", display:"flex", alignItems:"center", justifyContent:"center", fontSize:14 }}>⚡</div>
                    <span style={{ fontSize:11, color:C.muted, fontWeight:500 }}>Active Threats</span>
                    <span style={{ marginLeft:"auto", fontSize:10, color:C.dim }}>ⓘ</span>
                  </div>
                  {loading ? <Spinner size={18}/> : <>
                    <div style={{ fontSize:28, fontWeight:700, lineHeight:1 }}>{stats.activeThreats}</div>
                    <div style={{ fontSize:11, color:C.red, marginTop:5 }}>▲ 15% from last 7 days</div>
                    <MiniSparkline data={sparkThreats} color={C.red} height={36}/>
                  </>}
                </div>

                {/* Critical Incidents */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"16px 18px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:10 }}>
                    <div style={{ width:30, height:30, borderRadius:8, background:"#f9731622", display:"flex", alignItems:"center", justifyContent:"center", fontSize:14 }}>⚠️</div>
                    <span style={{ fontSize:11, color:C.muted, fontWeight:500 }}>Critical Incidents</span>
                    <span style={{ marginLeft:"auto", fontSize:10, color:C.dim }}>ⓘ</span>
                  </div>
                  {loading ? <Spinner size={18}/> : <>
                    <div style={{ fontSize:28, fontWeight:700, lineHeight:1 }}>{stats.criticalCount}</div>
                    <div style={{ fontSize:11, color:C.red, marginTop:5 }}>▲ 40% from last 7 days</div>
                    <MiniSparkline data={sparkCritical} color={C.orange} height={36}/>
                  </>}
                </div>

                {/* Connected Accounts */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"16px 18px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:10 }}>
                    <div style={{ width:30, height:30, borderRadius:8, background:"#3b82f622", display:"flex", alignItems:"center", justifyContent:"center", fontSize:14 }}>☁️</div>
                    <span style={{ fontSize:11, color:C.muted, fontWeight:500 }}>Connected Accounts</span>
                    <span style={{ marginLeft:"auto", fontSize:10, color:C.dim }}>ⓘ</span>
                  </div>
                  <div style={{ fontSize:28, fontWeight:700, lineHeight:1 }}>{accounts?.length ?? "—"}</div>
                  <div style={{ fontSize:11, color:C.muted, marginTop:5 }}>AWS Accounts</div>
                  <div style={{ height:36 }}/>
                </div>

                {/* Resources Protected */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"16px 18px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:10 }}>
                    <div style={{ width:30, height:30, borderRadius:8, background:"#a855f722", display:"flex", alignItems:"center", justifyContent:"center", fontSize:14 }}>🔷</div>
                    <span style={{ fontSize:11, color:C.muted, fontWeight:500 }}>Resources Protected</span>
                    <span style={{ marginLeft:"auto", fontSize:10, color:C.dim }}>ⓘ</span>
                  </div>
                  <div style={{ fontSize:28, fontWeight:700, lineHeight:1 }}>{coverage?.total_techniques_mapped ?? "—"}</div>
                  <div style={{ fontSize:11, color:C.green, marginTop:5 }}>+ 157 new this week</div>
                  <div style={{ height:36 }}/>
                </div>

                {/* Remediation Success */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"16px 18px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:10 }}>
                    <div style={{ width:30, height:30, borderRadius:8, background:"#22c55e22", display:"flex", alignItems:"center", justifyContent:"center", fontSize:14 }}>✅</div>
                    <span style={{ fontSize:11, color:C.muted, fontWeight:500 }}>Remediation Success</span>
                    <span style={{ marginLeft:"auto", fontSize:10, color:C.dim }}>ⓘ</span>
                  </div>
                  {loading ? <Spinner size={18}/> : <>
                    <div style={{ fontSize:28, fontWeight:700, lineHeight:1, color:C.green }}>{stats.successRate}%</div>
                    <div style={{ fontSize:11, color:C.green, marginTop:5 }}>▲ 6% from last 7 days</div>
                    <div style={{ height:36 }}/>
                  </>}
                </div>
              </div>

              {alertsError && <div style={{ marginBottom:14 }}><ErrorBanner message={alertsError} onRetry={refetchAlerts}/></div>}

              {/* ── Row 2: Threat Activity chart + Active Threats feed ── */}
              <div style={{ display:"grid", gridTemplateColumns:"1fr 380px", gap:16, marginBottom:16 }}>

                {/* Threat Activity */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"18px 20px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
                    <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                      <span style={{ fontSize:14, fontWeight:600 }}>Threat Activity</span>
                      <span style={{ fontSize:10, color:C.dim }}>ⓘ</span>
                    </div>
                    <div style={{ display:"flex", alignItems:"center", gap:16 }}>
                      {[["Critical",C.critical],["High",C.high],["Medium",C.medium],["Low",C.low]].map(([l,c])=>(
                        <div key={l} style={{ display:"flex", alignItems:"center", gap:5, fontSize:11, color:C.muted }}>
                          <div style={{ width:20, height:2, background:c, borderRadius:1 }}/>
                          {l}
                        </div>
                      ))}
                      <select style={{
                        background:C.hover, border:`1px solid ${C.cardBorder}`, borderRadius:6,
                        color:C.text, fontSize:11, padding:"4px 8px", cursor:"pointer", outline:"none",
                      }}>
                        <option>Last 7 Days</option>
                        <option>Last 14 Days</option>
                        <option>Last 30 Days</option>
                      </select>
                    </div>
                  </div>
                  {loading ? (
                    <div style={{ height:200, display:"flex", alignItems:"center", justifyContent:"center" }}><Spinner size={24}/></div>
                  ) : (
                    <ResponsiveContainer width="100%" height={200}>
                      <LineChart data={threatActivity} margin={{ top:5, right:10, bottom:0, left:-20 }}>
                        <XAxis dataKey="date" tick={{ fill:C.dim, fontSize:10 }} axisLine={false} tickLine={false}/>
                        <YAxis tick={{ fill:C.dim, fontSize:10 }} axisLine={false} tickLine={false} allowDecimals={false}/>
                        <Tooltip content={<ChartTooltip/>}/>
                        <Line type="monotone" dataKey="critical" stroke={C.critical} strokeWidth={2} dot={false} name="Critical"/>
                        <Line type="monotone" dataKey="high"     stroke={C.high}     strokeWidth={2} dot={false} name="High"/>
                        <Line type="monotone" dataKey="medium"   stroke={C.medium}   strokeWidth={2} dot={false} name="Medium"/>
                        <Line type="monotone" dataKey="low"      stroke={C.low}      strokeWidth={2} dot={false} name="Low"/>
                      </LineChart>
                    </ResponsiveContainer>
                  )}
                </div>

                {/* Active Threats feed */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"18px 20px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
                    <span style={{ fontSize:14, fontWeight:600 }}>Active Threats</span>
                    <span onClick={()=>setActiveNav("Alerts")} style={{ fontSize:12, color:C.accent, cursor:"pointer" }}>View all</span>
                  </div>
                  {loading ? (
                    <div style={{ display:"flex", justifyContent:"center", padding:24 }}><Spinner size={20}/></div>
                  ) : criticalAlerts.length === 0 ? (
                    <div style={{ textAlign:"center", padding:"32px 0", color:C.dim, fontSize:12 }}>
                      <div style={{ fontSize:32, marginBottom:8 }}>✅</div>
                      No active critical threats
                    </div>
                  ) : criticalAlerts.map(a => (
                    <div key={a.event_id}
                      onMouseEnter={e=>e.currentTarget.style.background=C.hover}
                      onMouseLeave={e=>e.currentTarget.style.background="transparent"}
                      style={{ display:"flex", alignItems:"flex-start", gap:10, padding:"9px 8px", borderRadius:8, cursor:"pointer", transition:"background 0.15s" }}>
                      <div style={{ width:32, height:32, borderRadius:8, background:`${SEV_COLOR[a.risk_tier]}18`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:14, flexShrink:0 }}>
                        {tacticIcon(a.tactic)}
                      </div>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:3, flexWrap:"wrap" }}>
                          <span style={{ fontSize:12, fontWeight:500 }}>{a.technique_name}</span>
                          <Badge sev={a.risk_tier} small/>
                        </div>
                        <div style={{ fontSize:11, color:C.dim, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                          AWS Account: {a.actor_arn?.split(":")?.[4] || "—"}
                        </div>
                      </div>
                      <div style={{ display:"flex", alignItems:"center", gap:4, flexShrink:0 }}>
                        <span style={{ fontSize:10, color:C.dim }}>{timeAgo(a.event_time)}</span>
                        <span style={{ color:C.dim }}>›</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* ── Row 3: Recent Incidents table + Recent Alerts feed ── */}
              <div style={{ display:"grid", gridTemplateColumns:"1fr 380px", gap:16, marginBottom:16 }}>

                {/* Recent Incidents */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"18px 20px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
                    <span style={{ fontSize:14, fontWeight:600 }}>Recent Incidents</span>
                    <span onClick={()=>setActiveNav("Incidents")} style={{ fontSize:12, color:C.accent, cursor:"pointer" }}>View all</span>
                  </div>
                  {loading ? (
                    <div style={{ display:"flex", justifyContent:"center", padding:24 }}><Spinner size={20}/></div>
                  ) : (
                    <table style={{ width:"100%", borderCollapse:"collapse" }}>
                      <thead>
                        <tr>
                          {["Incident","Severity","Status","Account","Time"].map(h=>(
                            <th key={h} style={{ textAlign:"left", padding:"6px 8px", fontSize:11, color:C.dim, fontWeight:500, borderBottom:`1px solid ${C.cardBorder}` }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {recentAlerts.length === 0 ? (
                          <tr><td colSpan={5} style={{ padding:"24px 0", textAlign:"center", color:C.dim, fontSize:12 }}>
                            No incidents. Run a scan to detect threats.
                          </td></tr>
                        ) : recentAlerts.map(inc=>(
                          <tr key={inc.event_id}
                            onMouseEnter={e=>e.currentTarget.style.background=C.hover}
                            onMouseLeave={e=>e.currentTarget.style.background="transparent"}
                            style={{ cursor:"pointer", transition:"background 0.12s" }}>
                            <td style={{ padding:"10px 8px" }}>
                              <div style={{ display:"flex", alignItems:"center", gap:7 }}>
                                <div style={{ width:7, height:7, borderRadius:"50%", background:SEV_COLOR[inc.risk_tier]||C.muted, flexShrink:0 }}/>
                                <span style={{ fontSize:12, maxWidth:200, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{inc.technique_name}</span>
                              </div>
                            </td>
                            <td style={{ padding:"10px 8px" }}><Badge sev={inc.risk_tier} small/></td>
                            <td style={{ padding:"10px 8px" }}><StatusBadge status={inc.status}/></td>
                            <td style={{ padding:"10px 8px", fontSize:11, color:C.muted, fontFamily:"monospace" }}>
                              {inc.actor_arn?.split(":")?.[4] || inc.region}
                            </td>
                            <td style={{ padding:"10px 8px", fontSize:11, color:C.dim }}>{timeAgo(inc.event_time)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>

                {/* Recent Alerts feed */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"18px 20px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
                    <span style={{ fontSize:14, fontWeight:600 }}>Recent Alerts</span>
                    <span onClick={()=>setActiveNav("Alerts")} style={{ fontSize:12, color:C.accent, cursor:"pointer" }}>View all</span>
                  </div>
                  {loading ? (
                    <div style={{ display:"flex", justifyContent:"center", padding:24 }}><Spinner size={20}/></div>
                  ) : recentAlerts.length === 0 ? (
                    <div style={{ textAlign:"center", padding:"24px 0", color:C.dim, fontSize:12 }}>No alerts yet.</div>
                  ) : recentAlerts.map(a=>(
                    <div key={a.event_id}
                      onMouseEnter={e=>e.currentTarget.style.background=C.hover}
                      onMouseLeave={e=>e.currentTarget.style.background="transparent"}
                      style={{ display:"flex", alignItems:"flex-start", gap:10, padding:"9px 8px", borderRadius:8, borderBottom:`1px solid ${C.cardBorder}`, cursor:"pointer", transition:"background 0.12s" }}>
                      <div style={{ width:32, height:32, borderRadius:8, background:C.hover, display:"flex", alignItems:"center", justifyContent:"center", fontSize:14, flexShrink:0 }}>
                        {tacticIcon(a.tactic)}
                      </div>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ fontSize:12, marginBottom:3, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                          {a.source === "guardduty" ? "GuardDuty finding: " : a.source === "config_scan" ? "Config scan: " : "CloudTrail: "}{a.event_name}
                        </div>
                        <div style={{ fontSize:11, color:C.dim }}>
                          AWS Account: {a.actor_arn?.split(":")?.[4] || a.region}
                        </div>
                      </div>
                      <div style={{ display:"flex", alignItems:"center", gap:6, flexShrink:0 }}>
                        <span style={{ fontSize:10, color:C.dim }}>{timeAgo(a.event_time)}</span>
                        <span style={{ color:C.dim }}>›</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* ── Row 4: Score Trend + Top Services + Compliance + Remediation Overview ── */}
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr", gap:14 }}>

                {/* Security Score Trend */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"18px 20px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:14 }}>
                    <span style={{ fontSize:14, fontWeight:600 }}>Security Score Trend</span>
                    <span style={{ fontSize:10, color:C.dim }}>ⓘ</span>
                  </div>
                  <ResponsiveContainer width="100%" height={120}>
                    <AreaChart data={scoreTrend} margin={{ top:5, right:0, bottom:0, left:-30 }}>
                      <defs>
                        <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor={C.green} stopOpacity={0.3}/>
                          <stop offset="95%" stopColor={C.green} stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="date" tick={{ fill:C.dim, fontSize:9 }} axisLine={false} tickLine={false} tickFormatter={d=>d.split(" ")[1]}/>
                      <YAxis tick={{ fill:C.dim, fontSize:9 }} axisLine={false} tickLine={false} domain={[0,100]}/>
                      <Tooltip content={<ChartTooltip/>}/>
                      <Area type="monotone" dataKey="score" stroke={C.green} strokeWidth={2} fill="url(#scoreGrad)" dot={false} name="Score"/>
                    </AreaChart>
                  </ResponsiveContainer>
                  <div style={{ textAlign:"right", marginTop:6 }}>
                    <span style={{ display:"inline-block", padding:"3px 9px", borderRadius:6, background:`${C.green}22`, color:C.green, fontSize:12, fontWeight:700 }}>
                      {stats.secScore}
                    </span>
                  </div>
                </div>

                {/* Top Targeted Services */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"18px 20px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:14 }}>
                    <span style={{ fontSize:14, fontWeight:600 }}>Top Targeted Services</span>
                    <span style={{ fontSize:10, color:C.dim }}>ⓘ</span>
                  </div>
                  {topServices.length === 0 ? (
                    <div style={{ textAlign:"center", padding:"24px 0", color:C.dim, fontSize:12 }}>No data yet</div>
                  ) : (
                    <div style={{ display:"flex", alignItems:"center", gap:14 }}>
                      <PieChart width={100} height={100}>
                        <Pie data={topServices} cx={45} cy={45} innerRadius={28} outerRadius={46}
                          dataKey="value" paddingAngle={2} startAngle={90} endAngle={-270}>
                          {topServices.map((s,i)=><Cell key={i} fill={s.color}/>)}
                        </Pie>
                      </PieChart>
                      <div style={{ flex:1, display:"flex", flexDirection:"column", gap:6 }}>
                        {topServices.map(s=>(
                          <div key={s.name} style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                            <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                              <div style={{ width:10, height:10, borderRadius:2, background:s.color }}/>
                              <span style={{ fontSize:11, color:C.muted }}>{s.name}</span>
                            </div>
                            <span style={{ fontSize:11, fontWeight:600 }}>{s.value}%</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Compliance Status */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"18px 20px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
                    <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                      <span style={{ fontSize:14, fontWeight:600 }}>Compliance Status</span>
                      <span style={{ fontSize:10, color:C.dim }}>ⓘ</span>
                    </div>
                    <span style={{ fontSize:12, color:C.accent, cursor:"pointer" }}>View all</span>
                  </div>
                  <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
                    {complianceData.map(c=>(
                      <div key={c.name}>
                        <div style={{ display:"flex", justifyContent:"space-between", marginBottom:5 }}>
                          <span style={{ fontSize:11, color:C.muted }}>{c.name}</span>
                          <span style={{ fontSize:11, fontWeight:700, color:c.color }}>{c.pct}%</span>
                        </div>
                        <div style={{ height:6, background:C.hover, borderRadius:3, overflow:"hidden" }}>
                          <div style={{ width:`${c.pct}%`, height:"100%", background:`linear-gradient(90deg,${c.color}88,${c.color})`, borderRadius:3, transition:"width 1s ease" }}/>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Remediation Overview */}
                <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"18px 20px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:14 }}>
                    <span style={{ fontSize:14, fontWeight:600 }}>Remediation Overview</span>
                    <span style={{ fontSize:10, color:C.dim }}>ⓘ</span>
                  </div>
                  <div style={{ display:"flex", alignItems:"center", gap:14 }}>
                    <div style={{ position:"relative", flexShrink:0 }}>
                      <PieChart width={100} height={100}>
                        <Pie data={remDonut} cx={45} cy={45} innerRadius={28} outerRadius={46}
                          dataKey="value" paddingAngle={2} startAngle={90} endAngle={-270}>
                          {remDonut.map((d,i)=><Cell key={i} fill={d.color}/>)}
                        </Pie>
                      </PieChart>
                      <div style={{ position:"absolute", top:"50%", left:"50%", transform:"translate(-50%,-50%)", textAlign:"center" }}>
                        <div style={{ fontSize:15, fontWeight:700 }}>{stats.total}</div>
                        <div style={{ fontSize:9, color:C.dim }}>Total</div>
                      </div>
                    </div>
                    <div style={{ flex:1, display:"flex", flexDirection:"column", gap:8 }}>
                      {remDonut.map(d=>(
                        <div key={d.name} style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                            <div style={{ width:8, height:8, borderRadius:2, background:d.color }}/>
                            <span style={{ fontSize:11, color:C.muted }}>{d.name}</span>
                          </div>
                          <span style={{ fontSize:11, fontWeight:600 }}>
                            {d.value}{stats.total>0?` (${Math.round(d.value/stats.total*100)}%)`:""}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </>
          )}


                    {/* ── Incidents page ── */}
          {activeNav === "Incidents" && (
            <div style={{ background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 12, padding: "20px 24px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>All Incidents</div>
                  <div style={{ fontSize: 12, color: C.muted }}>{allAlerts.length} total</div>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  {["All","Critical","High","Medium","Low"].map(f => (
                    <button key={f} style={{
                      padding: "5px 12px", borderRadius: 6, border: `1px solid ${C.cardBorder}`,
                      background: C.hover, color: C.muted, fontSize: 11, cursor: "pointer",
                    }}>{f}</button>
                  ))}
                </div>
              </div>
              {alertsLoading ? (
                <div style={{ display: "flex", justifyContent: "center", padding: 48 }}><Spinner size={28}/></div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>{["Technique", "Event", "Tactic", "Severity", "Status", "Actor", "Region", "Time"].map(h => (
                      <th key={h} style={{
                        textAlign: "left", padding: "8px 10px", fontSize: 11,
                        color: C.dim, fontWeight: 500, borderBottom: `1px solid ${C.cardBorder}`,
                      }}>{h}</th>
                    ))}</tr>
                  </thead>
                  <tbody>
                    {allAlerts.map(inc => (
                      <tr key={inc.event_id}
                        onMouseEnter={e => e.currentTarget.style.background = C.hover}
                        onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                        style={{ cursor: "pointer", transition: "background 0.12s" }}>
                        <td style={{ padding: "10px 10px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                            <div style={{ width: 7, height: 7, borderRadius: "50%", background: SEV_COLOR[inc.risk_tier], flexShrink: 0 }}/>
                            <span style={{ fontSize: 12, maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              {inc.technique_name}
                            </span>
                          </div>
                        </td>
                        <td style={{ padding: "10px 10px", fontSize: 11, color: C.muted, fontFamily: "monospace", maxWidth: 140 }}>
                          <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {inc.event_name}
                          </div>
                        </td>
                        <td style={{ padding: "10px 10px", fontSize: 11, color: C.muted }}>{inc.tactic}</td>
                        <td style={{ padding: "10px 10px" }}><Badge sev={inc.risk_tier} small/></td>
                        <td style={{ padding: "10px 10px" }}><StatusBadge status={inc.status}/></td>
                        <td style={{ padding: "10px 10px", fontSize: 11, color: C.muted, fontFamily: "monospace", maxWidth: 120 }}>
                          <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {inc.actor_arn?.split("/").pop() || "—"}
                          </div>
                        </td>
                        <td style={{ padding: "10px 10px", fontSize: 11, color: C.muted }}>{inc.region}</td>
                        <td style={{ padding: "10px 10px", fontSize: 11, color: C.dim }}>{timeAgo(inc.event_time)}</td>
                      </tr>
                    ))}
                    {allAlerts.length === 0 && (
                      <tr><td colSpan={8} style={{ padding: "40px 0", textAlign: "center", color: C.dim, fontSize: 12 }}>
                        No incidents found. Run a scan to start detecting threats.
                      </td></tr>
                    )}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* ── Remediation page ── */}
          {activeNav === "Remediation" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {/* Pending approvals */}
              <div style={{ background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 12, padding: "20px 24px" }}>
                <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>Pending Approvals</div>
                <div style={{ fontSize: 12, color: C.muted, marginBottom: 20 }}>
                  {pendingList.length > 0
                    ? `${pendingList.length} action${pendingList.length > 1 ? "s" : ""} awaiting your approval`
                    : "No pending approvals"}
                </div>

                {pendingLoading ? (
                  <div style={{ display: "flex", justifyContent: "center", padding: 32 }}><Spinner size={24}/></div>
                ) : pendingList.length === 0 ? (
                  <div style={{ textAlign: "center", padding: "32px 0", color: C.dim, fontSize: 12 }}>
                    <div style={{ fontSize: 32, marginBottom: 8 }}>✅</div>
                    No actions pending approval
                  </div>
                ) : pendingList.map(a => (
                  <div key={a.event_id} style={{
                    border: `1px solid ${C.cardBorder}`, borderRadius: 10,
                    padding: "16px 18px", marginBottom: 10,
                    borderLeft: `3px solid ${SEV_COLOR[a.risk_tier] || C.muted}`,
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                          <span style={{ fontSize: 13, fontWeight: 600 }}>{a.technique_name}</span>
                          <Badge sev={a.risk_tier}/>
                        </div>
                        <div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>
                          Event: <code style={{ color: C.text }}>{a.event_name}</code>
                        </div>
                        <div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>
                          Actor: <code style={{ color: C.text, fontSize: 11 }}>{a.actor_arn}</code>
                        </div>
                        <div style={{ fontSize: 11, color: C.dim }}>
                          Tactic: {a.tactic} · Region: {a.region} · {timeAgo(a.event_time)}
                        </div>
                        {a.remediation_action && (
                          <div style={{ marginTop: 8, padding: "6px 10px", borderRadius: 6,
                            background: "#1e2a3a", fontSize: 11, color: C.muted }}>
                            Planned action: <strong style={{ color: C.text }}>{a.remediation_action}</strong>
                          </div>
                        )}
                        {approveMsg[a.event_id] && (
                          <div style={{ marginTop: 8, fontSize: 11,
                            color: approveMsg[a.event_id].ok ? C.green : C.red }}>
                            {approveMsg[a.event_id].ok ? "✓" : "⚠"} {approveMsg[a.event_id].text}
                          </div>
                        )}
                      </div>
                      <div style={{ display: "flex", gap: 8, flexShrink: 0, marginLeft: 16 }}>
                        <button onClick={() => handleDismiss(a.event_id)} style={{
                          padding: "7px 14px", borderRadius: 6, border: `1px solid ${C.cardBorder}`,
                          background: "transparent", color: C.muted, fontSize: 12, cursor: "pointer",
                        }}>Dismiss</button>
                        <button onClick={() => handleApprove(a.event_id)}
                          disabled={approvingId === a.event_id} style={{
                          padding: "7px 14px", borderRadius: 6, border: "none",
                          background: C.accent, color: "#fff", fontSize: 12, fontWeight: 600,
                          cursor: approvingId === a.event_id ? "not-allowed" : "pointer",
                          opacity: approvingId === a.event_id ? 0.7 : 1,
                          display: "flex", alignItems: "center", gap: 6,
                        }}>
                          {approvingId === a.event_id && <Spinner size={12}/>}
                          Approve & Execute
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Remediation history */}
              <div style={{ background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 12, padding: "20px 24px" }}>
                <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>Remediation History</div>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>{["Technique", "Action", "Severity", "Outcome", "Time"].map(h => (
                      <th key={h} style={{
                        textAlign: "left", padding: "6px 10px", fontSize: 11,
                        color: C.dim, fontWeight: 500, borderBottom: `1px solid ${C.cardBorder}`,
                      }}>{h}</th>
                    ))}</tr>
                  </thead>
                  <tbody>
                    {allAlerts.filter(a => ["remediated","remediation_failed","false_positive"].includes(a.status)).map(a => (
                      <tr key={a.event_id}
                        onMouseEnter={e => e.currentTarget.style.background = C.hover}
                        onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                        <td style={{ padding: "10px 10px", fontSize: 12 }}>{a.technique_name}</td>
                        <td style={{ padding: "10px 10px", fontSize: 11, color: C.muted, fontFamily: "monospace" }}>
                          {a.remediation_action || "—"}
                        </td>
                        <td style={{ padding: "10px 10px" }}><Badge sev={a.risk_tier} small/></td>
                        <td style={{ padding: "10px 10px" }}><StatusBadge status={a.status}/></td>
                        <td style={{ padding: "10px 10px", fontSize: 11, color: C.dim }}>{timeAgo(a.event_time)}</td>
                      </tr>
                    ))}
                    {allAlerts.filter(a => ["remediated","remediation_failed","false_positive"].includes(a.status)).length === 0 && (
                      <tr><td colSpan={5} style={{ padding: "32px 0", textAlign: "center", color: C.dim, fontSize: 12 }}>
                        No remediation history yet.
                      </td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Alerts page ── */}
          {activeNav === "Alerts" && (
            <div style={{ background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 12, padding: "20px 24px" }}>
              <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>All Alerts</div>
              {alertsLoading ? (
                <div style={{ display: "flex", justifyContent: "center", padding: 48 }}><Spinner size={28}/></div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {allAlerts.map(a => (
                    <div key={a.event_id} style={{
                      display: "flex", alignItems: "center", gap: 14, padding: "12px 10px",
                      borderRadius: 8, borderBottom: `1px solid ${C.cardBorder}`,
                      cursor: "pointer",
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = C.hover}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                      <div style={{
                        width: 36, height: 36, borderRadius: 9,
                        background: `${SEV_COLOR[a.risk_tier]}18`,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        fontSize: 16, flexShrink: 0,
                      }}>{tacticIcon(a.tactic)}</div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 2 }}>{a.technique_name}</div>
                        <div style={{ fontSize: 11, color: C.muted }}>
                          {a.event_name} · {a.tactic} · {a.region}
                        </div>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
                        <Badge sev={a.risk_tier} small/>
                        <StatusBadge status={a.status}/>
                        <span style={{ fontSize: 11, color: C.dim, minWidth: 60, textAlign: "right" }}>
                          {timeAgo(a.event_time)}
                        </span>
                      </div>
                    </div>
                  ))}
                  {allAlerts.length === 0 && (
                    <div style={{ textAlign: "center", padding: "48px 0", color: C.dim, fontSize: 12 }}>
                      No alerts found. Try running a scan.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ── AWS Accounts page ── */}
          {activeNav === "Settings" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 12, padding: "20px 24px" }}>
                <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>System Status</div>
                <div style={{ fontSize: 12, color: C.muted, marginBottom: 20 }}>API and AWS connectivity</div>
                {healthLoading ? (
                  <Spinner/>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {[
                      ["API Status", health?.status || "unknown", health?.status === "healthy" ? C.green : C.orange],
                      ["AWS Region", health?.region || "—", C.text],
                      ["CloudTrail", health?.cloudtrail_accessible ? "Accessible" : "Not accessible",
                        health?.cloudtrail_accessible ? C.green : C.red],
                      ["GuardDuty", health?.guardduty_enabled ? "Enabled" : "Not enabled",
                        health?.guardduty_enabled ? C.green : C.orange],
                      ["ML Model", health?.model_loaded ? "Loaded" : "Not trained",
                        health?.model_loaded ? C.green : C.yellow],
                      ["Remediation", health?.remediation_enabled ? "Live mode" : "Dry-run mode",
                        health?.remediation_enabled ? C.green : C.yellow],
                      ["Storage", health?.storage_backend || "—", C.text],
                      ["AWS Account", health?.aws_account || "—", C.muted],
                    ].map(([label, value, color]) => (
                      <div key={label} style={{
                        display: "flex", justifyContent: "space-between", alignItems: "center",
                        padding: "10px 14px", borderRadius: 8, background: C.hover,
                      }}>
                        <span style={{ fontSize: 13, color: C.muted }}>{label}</span>
                        <span style={{ fontSize: 13, fontWeight: 600, color, textTransform: "capitalize" }}>{value}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div style={{ background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 12, padding: "20px 24px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 4 }}>
                  <div>
                    <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>Connected AWS Accounts</div>
                    <div style={{ fontSize: 12, color: C.muted, marginBottom: 16 }}>
                      {accounts?.length || 0} account{accounts?.length !== 1 ? "s" : ""} connected
                    </div>
                  </div>
                  <button onClick={() => setActiveNav("AWS Accounts")} style={{
                    padding: "7px 14px", borderRadius: 8, border: `1px solid ${C.cardBorder}`,
                    background: "transparent", color: C.accent, fontSize: 12, fontWeight: 600, cursor: "pointer",
                  }}>
                    Manage accounts →
                  </button>
                </div>
                {(accounts || []).length === 0 ? (
                  <div style={{ textAlign: "center", padding: "32px 0", color: C.dim, fontSize: 12 }}>
                    No AWS accounts connected yet.{" "}
                    <span onClick={() => setActiveNav("AWS Accounts")} style={{ color: C.accent, cursor: "pointer", fontWeight: 600 }}>
                      Connect your first account →
                    </span>
                  </div>
                ) : (accounts || []).map(acc => (
                  <div key={acc.id} style={{
                    padding: "14px 16px", borderRadius: 10,
                    border: `1px solid ${C.cardBorder}`, marginBottom: 10,
                    display: "flex", justifyContent: "space-between", alignItems: "center",
                  }}>
                    <div>
                      <div style={{ fontWeight: 600, marginBottom: 4 }}>{acc.display_name}</div>
                      <div style={{ fontSize: 11, color: C.muted, fontFamily: "monospace" }}>{acc.aws_account_id}</div>
                      <div style={{ fontSize: 11, color: C.dim, marginTop: 2 }}>{acc.primary_region}</div>
                    </div>
                    <div style={{ display: "flex", align: "center", gap: 8 }}>
                      <span style={{
                        padding: "4px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600,
                        background: acc.status === "active" ? `${C.green}22` : `${C.yellow}22`,
                        color: acc.status === "active" ? C.green : C.yellow,
                      }}>{acc.status}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}



          {/* ── Attack simulator page ── */}
          {activeNav === "Attack Simulator" && <AttackSimulatorPage />}

          {/* ── Learning page ── */}
          {activeNav === "Learning" && (
            <LearningPage authHeaders={me ? { Authorization: `Bearer ${getToken()}` } : {}} />
          )}

          {/* ── Billing page ── */}
          {activeNav === "Billing" && (
            <BillingPage authHeaders={me ? { Authorization: `Bearer ${getToken()}` } : {}} />
          )}

          {/* ── AWS Accounts page ── */}
          {activeNav === "AWS Accounts" && (
            <AWSAccountsPage accounts={accounts} onRefetch={refetchAccounts} />
          )}

          {/* Placeholder for other nav pages */}
          {!["Overview","Incidents","Remediation","Alerts","Billing","Learning","Settings","AWS Accounts","Attack Simulator"].includes(activeNav) && (
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              minHeight: 400, flexDirection: "column", gap: 12, color: C.dim,
            }}>
              <div style={{ fontSize: 48 }}>🚧</div>
              <div style={{ fontSize: 16, fontWeight: 600, color: C.muted }}>{activeNav}</div>
              <div style={{ fontSize: 12 }}>This page is coming in the next build sprint.</div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

function AttackSimulatorPage() {
  const [report, setReport] = useState(null);
  const [scenarios, setScenarios] = useState([]);
  const [loading, setLoading] = useState(false);
  const [pageLoading, setPageLoading] = useState(true);
  const [error, setError] = useState(null);
  const [threshold, setThreshold] = useState(30);

  const load = useCallback(async () => {
    setPageLoading(true);
    try {
      const [latest, scenarioData] = await Promise.all([
        api("/simulator/latest"),
        api("/simulator/scenarios"),
      ]);
      setReport(latest.report || null);
      setScenarios(scenarioData.scenarios || []);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setPageLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function runEvaluation() {
    setLoading(true); setError(null);
    try {
      const result = await api(`/simulator/run?threshold=${threshold}`, { method: "POST" });
      setReport(result);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  const metric = (label, value) => (
    <div style={{ background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 10, padding: 16 }}>
      <div style={{ color: C.muted, fontSize: 11, marginBottom: 8 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 700 }}>{value == null ? "N/A" : `${Math.round(value * 100)}%`}</div>
    </div>
  );

  return (
    <div style={{ padding: 24, maxWidth: 1200, margin: "0 auto" }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, flexWrap: "wrap", marginBottom: 22 }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 6 }}>Attack Simulator & Evaluation</div>
          <div style={{ color: C.muted, lineHeight: 1.6, maxWidth: 700 }}>
            Run safe, offline synthetic events through the current rule engine and measure detection quality. This does not attack AWS resources or execute remediation.
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <label style={{ color: C.muted, fontSize: 12 }}>Alert threshold</label>
          <select value={threshold} onChange={e => setThreshold(Number(e.target.value))} style={{ background: C.sidebar, color: C.text, border: `1px solid ${C.cardBorder}`, borderRadius: 6, padding: "8px 10px" }}>
            {[10, 20, 30, 40, 50, 60].map(n => <option key={n} value={n}>{n}/100</option>)}
          </select>
          <button onClick={runEvaluation} disabled={loading} style={{ background: C.accent, color: "#fff", border: 0, borderRadius: 7, padding: "9px 14px", cursor: loading ? "wait" : "pointer", fontWeight: 600 }}>
            {loading ? "Running…" : "Run evaluation"}
          </button>
        </div>
      </div>

      <div style={{ background: "#172554", border: "1px solid #1d4ed8", color: "#bfdbfe", borderRadius: 8, padding: 12, marginBottom: 18, lineHeight: 1.5, fontSize: 12 }}>
        Simulation mode: synthetic/offline. MTTD is reported as zero for in-process detections and is not representative of production CloudTrail ingestion latency. Remediation success is not measured.
      </div>

      {error && <div style={{ color: C.red, background: `${C.red}12`, border: `1px solid ${C.red}44`, padding: 12, borderRadius: 8, marginBottom: 16 }}>{error}</div>}
      {pageLoading ? <div style={{ color: C.muted, padding: 20 }}>Loading evaluation data…</div> : <>
        {report && <>
          <div style={{ color: C.muted, fontSize: 11, marginBottom: 10 }}>
            Latest run: <span style={{ color: C.text }}>{report.run_id}</span> · {report.scenario_count} scenarios · {report.generated_at ? new Date(report.generated_at).toLocaleString() : ""}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))", gap: 10, marginBottom: 18 }}>
            {metric("Precision", report.metrics?.precision)}
            {metric("Recall / detection rate", report.metrics?.recall_detection_rate)}
            {metric("F1 score", report.metrics?.f1_score)}
            {metric("Accuracy", report.metrics?.accuracy)}
            {metric("False-positive rate", report.metrics?.false_positive_rate)}
            {metric("MITRE mapping accuracy", report.metrics?.mitre_mapping_accuracy)}
          </div>
          <div style={{ background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 10, padding: 16, marginBottom: 18 }}>
            <div style={{ fontWeight: 700, marginBottom: 12 }}>Confusion matrix</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(120px,1fr))", gap: 12 }}>
              {Object.entries(report.confusion_matrix || {}).map(([key, value]) => (
                <div key={key}><div style={{ color: C.muted, fontSize: 11, textTransform: "capitalize" }}>{key.replaceAll("_", " ")}</div><div style={{ fontSize: 22, fontWeight: 700 }}>{value}</div></div>
              ))}
            </div>
          </div>
          <div style={{ background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 10, overflow: "hidden", marginBottom: 18 }}>
            <div style={{ padding: 16, fontWeight: 700, borderBottom: `1px solid ${C.cardBorder}` }}>Scenario results</div>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 680 }}>
                <thead><tr>{["Scenario","Expected","Result","Severity","MITRE mapping"].map(h => <th key={h} style={{ textAlign: "left", padding: 12, color: C.muted, fontSize: 11, borderBottom: `1px solid ${C.cardBorder}` }}>{h}</th>)}</tr></thead>
                <tbody>{(report.results || []).map(row => <tr key={row.scenario_id}>
                  <td style={{ padding: 12, borderBottom: `1px solid ${C.cardBorder}` }}><div style={{ fontWeight: 600 }}>{row.scenario_name}</div><div style={{ color: C.dim, fontSize: 10, marginTop: 3 }}>{row.event_name}</div></td>
                  <td style={{ padding: 12, borderBottom: `1px solid ${C.cardBorder}` }}>{row.expected_detection ? "Detect" : "Benign"}</td>
                  <td style={{ padding: 12, borderBottom: `1px solid ${C.cardBorder}`, color: row.detected === row.expected_detection ? C.green : C.red }}>{row.detected ? "Detected" : row.expected_detection ? "Missed" : "Not detected"}</td>
                  <td style={{ padding: 12, borderBottom: `1px solid ${C.cardBorder}` }}>{row.severity == null ? "—" : `${row.severity}/100`}</td>
                  <td style={{ padding: 12, borderBottom: `1px solid ${C.cardBorder}`, color: row.mapping_match ? C.green : row.expected_technique_id ? C.red : C.muted }}>{row.actual_technique_id || "Unmapped"}{row.expected_technique_id && row.actual_technique_id !== row.expected_technique_id ? ` (expected ${row.expected_technique_id})` : ""}</td>
                </tr>)}</tbody>
              </table>
            </div>
          </div>
        </>}
        <div style={{ background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 10, overflow: "hidden" }}>
          <div style={{ padding: 16, fontWeight: 700, borderBottom: `1px solid ${C.cardBorder}` }}>Available synthetic scenarios ({scenarios.length})</div>
          {scenarios.map(s => <div key={s.id} style={{ padding: "12px 16px", borderBottom: `1px solid ${C.cardBorder}` }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}><span style={{ fontWeight: 600 }}>{s.name}</span><span style={{ color: s.expected_detection ? C.orange : C.green, fontSize: 11 }}>{s.expected_detection ? "Expected detection" : "Benign control"}</span></div>
            <div style={{ color: C.muted, fontSize: 11, marginTop: 5 }}>{s.description}</div>
          </div>)}
        </div>
      </>}
    </div>
  );
}


function AccountStatusPill({ status }) {
  const map = {
    active:       { bg: `${C.green}22`,  fg: C.green,  label: "Active" },
    pending:      { bg: `${C.yellow}22`, fg: C.yellow, label: "Pending" },
    error:        { bg: `${C.red}22`,    fg: C.red,    label: "Error" },
    disconnected: { bg: `${C.dim}33`,    fg: C.muted,  label: "Disconnected" },
  };
  const s = map[status] || map.pending;
  return (
    <span style={{
      padding: "3px 9px", borderRadius: 6, fontSize: 11, fontWeight: 600,
      background: s.bg, color: s.fg,
    }}>{s.label}</span>
  );
}

function isValidRoleArn(arn) {
  return /^arn:aws:iam::\d{12}:role\/[\w+=,.@-]+$/.test((arn || "").trim());
}

function AWSAccountsPage({ accounts, onRefetch }) {
  const inp = {
    width: "100%", padding: "10px 12px", borderRadius: 8, fontSize: 13,
    background: C.hover, border: `1px solid ${C.cardBorder}`, color: C.text, outline: "none",
  };
  const label = { fontSize: 12, color: C.muted, marginBottom: 6, display: "block", fontWeight: 600 };
  const btnPrimary = {
    padding: "9px 16px", borderRadius: 8, border: "none",
    background: C.accent, color: "#fff", fontSize: 13, fontWeight: 600, cursor: "pointer",
  };
  const btnSecondary = {
    padding: "9px 16px", borderRadius: 8, border: `1px solid ${C.cardBorder}`,
    background: "transparent", color: C.muted, fontSize: 13, fontWeight: 600, cursor: "pointer",
  };
  const card = { background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 12, padding: "24px" };

  const [wizardOpen, setWizardOpen] = useState(false);
  const [step, setStep] = useState(1);
  const [setupTab, setSetupTab] = useState("cloudformation"); // "cloudformation" | "manual"
  const [form, setForm] = useState({ aws_account_id: "", display_name: "", primary_region: "us-east-1" });
  const [guide, setGuide] = useState(null);
  const [cfnTemplate, setCfnTemplate] = useState(null);
  const [roleArn, setRoleArn] = useState("");
  const [connectedAccount, setConnectedAccount] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [removingId, setRemovingId] = useState(null);
  const [reverifyingId, setReverifyingId] = useState(null);
  const [copied, setCopied] = useState(null);

  function resetWizard() {
    setWizardOpen(false); setStep(1); setSetupTab("cloudformation");
    setForm({ aws_account_id: "", display_name: "", primary_region: "us-east-1" });
    setGuide(null); setCfnTemplate(null); setRoleArn("");
    setConnectedAccount(null); setVerifyResult(null); setError(null);
  }

  function copy(text, key) {
    navigator.clipboard?.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 1500);
  }

  async function handleStartSetup() {
    setError(null);
    if (!/^\d{12}$/.test(form.aws_account_id.trim())) {
      setError("AWS account ID must be exactly 12 digits.");
      return;
    }
    if (!form.display_name.trim()) {
      setError("Give this account a name (e.g. \"Production\" or \"Client — Acme Corp\").");
      return;
    }
    setLoading(true);
    try {
      const [g, t] = await Promise.all([
        api(`/accounts/setup-guide?aws_account_id=${form.aws_account_id.trim()}`),
        api(`/accounts/cloudformation-template?aws_account_id=${form.aws_account_id.trim()}`),
      ]);
      setGuide(g);
      setCfnTemplate(t);
      setStep(2);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function downloadTemplate() {
    if (!cfnTemplate) return;
    const blob = new Blob([JSON.stringify(cfnTemplate.template, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = cfnTemplate.filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  async function handleConnect() {
    setError(null);
    if (!isValidRoleArn(roleArn)) {
      setError(`That doesn't look like a role ARN. Expected format: arn:aws:iam::${form.aws_account_id}:role/${guide?.role_name || "CloudGuardianDetectionRole"}`);
      return;
    }
    setLoading(true);
    try {
      const acc = await api("/accounts", {
        method: "POST",
        body: {
          aws_account_id: form.aws_account_id.trim(),
          display_name: form.display_name.trim(),
          role_arn: roleArn.trim(),
          primary_region: form.primary_region,
        },
      });
      setConnectedAccount(acc);
      onRefetch?.();
      setStep(4);
      await handleVerify(acc.id);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify(accountId) {
    setLoading(true); setError(null); setVerifyResult(null);
    try {
      const res = await api(`/accounts/${accountId}/verify`, { method: "POST" });
      setVerifyResult({ ok: true, ...res });
      onRefetch?.();
    } catch (e) {
      setVerifyResult({ ok: false, error: e.message });
    } finally {
      setLoading(false);
    }
  }

  async function handleReverify(accountId) {
    setReverifyingId(accountId);
    try {
      await api(`/accounts/${accountId}/verify`, { method: "POST" });
    } catch (e) {
      // surfaced on the account card via last_error after refetch
    } finally {
      onRefetch?.();
      setReverifyingId(null);
    }
  }

  async function handleRemove(accountId) {
    if (!window.confirm("Remove this AWS account? Cloud Guardian will stop scanning it immediately. Past incidents are kept for history.")) return;
    setRemovingId(accountId);
    try {
      await api(`/accounts/${accountId}`, { method: "DELETE" });
      onRefetch?.();
    } catch (e) {
      setError(e.message);
    } finally {
      setRemovingId(null);
    }
  }

  const steps = ["Account details", "Grant access", "Connect", "Verify"];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div style={{ fontSize: 20, fontWeight: 700 }}>AWS Accounts</div>
          <div style={{ fontSize: 13, color: C.muted, marginTop: 2 }}>
            Connect an AWS account for Cloud Guardian to scan. No access keys — we assume a
            read-only IAM role scoped to your account with a unique external ID.
          </div>
        </div>
        {!wizardOpen && (
          <button onClick={() => setWizardOpen(true)} style={btnPrimary}>+ Connect AWS Account</button>
        )}
      </div>

      {!wizardOpen && (
        <>
          {(accounts || []).length === 0 ? (
            <div style={{ ...card, textAlign: "center", padding: "48px 24px" }}>
              <div style={{ fontSize: 40, marginBottom: 12 }}>☁️</div>
              <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>No AWS accounts connected yet</div>
              <div style={{ fontSize: 13, color: C.muted, marginBottom: 20 }}>
                Connect your first account to start scanning for misconfigurations.
              </div>
              <button onClick={() => setWizardOpen(true)} style={{ ...btnPrimary, margin: "0 auto" }}>
                + Connect AWS Account
              </button>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {accounts.map(acc => (
                <div key={acc.id} style={{
                  ...card, padding: "16px 20px",
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                }}>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
                      <span style={{ fontWeight: 600, fontSize: 14 }}>{acc.display_name}</span>
                      <AccountStatusPill status={acc.status} />
                    </div>
                    <div style={{ fontSize: 11, color: C.muted, fontFamily: "monospace" }}>
                      {acc.aws_account_id} · {acc.primary_region}
                    </div>
                    <div style={{ fontSize: 11, color: C.dim, marginTop: 4 }}>
                      {acc.cloudtrail_enabled ? "✓ CloudTrail" : "— CloudTrail"} · {acc.guardduty_enabled ? "✓ GuardDuty" : "— GuardDuty"} · Last scan: {acc.last_scan_at ? timeAgo(acc.last_scan_at) : "never"}
                    </div>
                    {acc.status === "error" && acc.last_error && (
                      <div style={{ fontSize: 11, color: C.red, marginTop: 5, maxWidth: 460 }}>{acc.last_error}</div>
                    )}
                  </div>
                  <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
                    <button onClick={() => handleReverify(acc.id)} disabled={reverifyingId === acc.id}
                      style={{ ...btnSecondary, opacity: reverifyingId === acc.id ? 0.6 : 1 }}>
                      {reverifyingId === acc.id ? "Verifying…" : "Re-verify"}
                    </button>
                    <button onClick={() => handleRemove(acc.id)} disabled={removingId === acc.id}
                      style={{ ...btnSecondary, color: C.red, borderColor: `${C.red}44`, opacity: removingId === acc.id ? 0.6 : 1 }}>
                      {removingId === acc.id ? "Removing…" : "Remove"}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {wizardOpen && (
        <div style={{ ...card, padding: "28px 32px" }}>
          {/* Step indicator */}
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 28 }}>
            {steps.map((s, i) => (
              <div key={s} style={{ display: "flex", alignItems: "center", gap: 6, flex: i < steps.length - 1 ? 1 : "none" }}>
                <div style={{
                  width: 24, height: 24, borderRadius: "50%", flexShrink: 0,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 11, fontWeight: 700,
                  background: step > i + 1 ? C.green : step === i + 1 ? C.accent : C.hover,
                  color: step >= i + 1 ? "#fff" : C.dim,
                }}>{step > i + 1 ? "✓" : i + 1}</div>
                <span style={{ fontSize: 12, color: step === i + 1 ? C.text : C.dim, whiteSpace: "nowrap" }}>{s}</span>
                {i < steps.length - 1 && <div style={{ flex: 1, height: 1, background: C.cardBorder, marginLeft: 4 }} />}
              </div>
            ))}
          </div>

          {error && <ErrorBanner message={error} onRetry={() => setError(null)} />}

          {/* Step 1: account details */}
          {step === 1 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16, maxWidth: 440 }}>
              <div>
                <span style={label}>AWS Account ID</span>
                <input style={inp} placeholder="123456789012" maxLength={12}
                  value={form.aws_account_id}
                  onChange={e => setForm({ ...form, aws_account_id: e.target.value.replace(/\D/g, "") })} />
              </div>
              <div>
                <span style={label}>Display name</span>
                <input style={inp} placeholder="Production, Client — Acme Corp, etc."
                  value={form.display_name}
                  onChange={e => setForm({ ...form, display_name: e.target.value })} />
              </div>
              <div>
                <span style={label}>Primary region</span>
                <select style={inp} value={form.primary_region}
                  onChange={e => setForm({ ...form, primary_region: e.target.value })}>
                  {["us-east-1","us-east-2","us-west-1","us-west-2","eu-west-1","eu-central-1","ap-southeast-1","ap-southeast-2"].map(r => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>
              </div>
              <div style={{ display: "flex", gap: 10, marginTop: 8 }}>
                <button onClick={handleStartSetup} disabled={loading} style={{ ...btnPrimary, opacity: loading ? 0.6 : 1 }}>
                  {loading ? "Loading…" : "Continue"}
                </button>
                <button onClick={resetWizard} style={btnSecondary}>Cancel</button>
              </div>
            </div>
          )}

          {/* Step 2: grant access */}
          {step === 2 && guide && (
            <div>
              <div style={{ display: "flex", gap: 4, marginBottom: 18, borderBottom: `1px solid ${C.cardBorder}` }}>
                {[["cloudformation", "CloudFormation (recommended)"], ["manual", "Manual IAM setup"]].map(([k, l]) => (
                  <button key={k} onClick={() => setSetupTab(k)} style={{
                    padding: "8px 14px", border: "none", background: "transparent", cursor: "pointer",
                    fontSize: 12, fontWeight: 600,
                    color: setupTab === k ? C.accent : C.muted,
                    borderBottom: setupTab === k ? `2px solid ${C.accent}` : "2px solid transparent",
                  }}>{l}</button>
                ))}
              </div>

              {setupTab === "cloudformation" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 14, maxWidth: 560 }}>
                  <div style={{ fontSize: 13, color: C.muted }}>
                    This template creates <code style={{ color: C.text }}>{guide.role_name}</code> in your
                    account with the trust policy and read-only permissions already filled in —
                    nothing to edit.
                  </div>
                  <button onClick={downloadTemplate} style={{ ...btnPrimary, alignSelf: "flex-start" }}>
                    ⬇ Download CloudFormation template
                  </button>
                  <ol style={{ fontSize: 13, color: C.muted, paddingLeft: 20, margin: 0, display: "flex", flexDirection: "column", gap: 6 }}>
                    <li>Open the <a href={cfnTemplate?.console_create_stack_url} target="_blank" rel="noreferrer" style={{ color: C.accent }}>CloudFormation console</a> in the account you want to connect.</li>
                    <li>Choose "Upload a template file" and select the file you just downloaded.</li>
                    <li>Acknowledge the IAM capability checkbox and create the stack.</li>
                    <li>Once <code>CREATE_COMPLETE</code>, open the stack's <b>Outputs</b> tab and copy the <code>RoleArn</code> value.</li>
                  </ol>
                </div>
              )}

              {setupTab === "manual" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                  <ol style={{ fontSize: 13, color: C.muted, paddingLeft: 20, margin: 0, display: "flex", flexDirection: "column", gap: 6 }}>
                    {guide.instructions.map((line, i) => <li key={i}>{line}</li>)}
                  </ol>
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                      <span style={label}>Trust policy (paste into the role's trust relationship)</span>
                      <button onClick={() => copy(JSON.stringify(guide.trust_policy, null, 2), "trust")} style={{ ...btnSecondary, padding: "4px 10px", fontSize: 11 }}>
                        {copied === "trust" ? "Copied ✓" : "Copy"}
                      </button>
                    </div>
                    <pre style={{
                      background: C.hover, border: `1px solid ${C.cardBorder}`, borderRadius: 8,
                      padding: 12, fontSize: 11, color: C.text, overflowX: "auto", margin: 0,
                    }}>{JSON.stringify(guide.trust_policy, null, 2)}</pre>
                  </div>
                </div>
              )}

              <div style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                marginTop: 18, padding: "10px 14px", background: C.hover, borderRadius: 8,
              }}>
                <span style={{ fontSize: 11, color: C.muted }}>External ID (already baked into the template above)</span>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <code style={{ fontSize: 12, color: C.text }}>{guide.external_id}</code>
                  <button onClick={() => copy(guide.external_id, "extid")} style={{ ...btnSecondary, padding: "4px 10px", fontSize: 11 }}>
                    {copied === "extid" ? "Copied ✓" : "Copy"}
                  </button>
                </div>
              </div>

              <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
                <button onClick={() => setStep(3)} style={btnPrimary}>I've created the role — Continue</button>
                <button onClick={() => setStep(1)} style={btnSecondary}>Back</button>
              </div>
            </div>
          )}

          {/* Step 3: connect */}
          {step === 3 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16, maxWidth: 520 }}>
              <div>
                <span style={label}>Role ARN</span>
                <input style={inp}
                  placeholder={`arn:aws:iam::${form.aws_account_id}:role/${guide?.role_name || "CloudGuardianDetectionRole"}`}
                  value={roleArn} onChange={e => setRoleArn(e.target.value)} />
                <div style={{ fontSize: 11, color: C.dim, marginTop: 6 }}>
                  Find this on the role's summary page in IAM, or in the CloudFormation stack's Outputs tab.
                </div>
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <button onClick={handleConnect} disabled={loading} style={{ ...btnPrimary, opacity: loading ? 0.6 : 1 }}>
                  {loading ? "Connecting…" : "Connect account"}
                </button>
                <button onClick={() => setStep(2)} style={btnSecondary}>Back</button>
              </div>
            </div>
          )}

          {/* Step 4: verify */}
          {step === 4 && (
            <div style={{ maxWidth: 520 }}>
              {loading && !verifyResult && (
                <div style={{ display: "flex", alignItems: "center", gap: 10, color: C.muted, fontSize: 13 }}>
                  <Spinner /> Assuming the role and validating access…
                </div>
              )}

              {verifyResult?.ok && (
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                    <div style={{
                      width: 36, height: 36, borderRadius: "50%", background: `${C.green}22`,
                      display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, color: C.green,
                    }}>✓</div>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 15 }}>Connection verified</div>
                      <div style={{ fontSize: 12, color: C.muted }}>Cloud Guardian successfully assumed the role.</div>
                    </div>
                  </div>
                  <div style={{ background: C.hover, borderRadius: 8, padding: 14, fontSize: 12, color: C.muted, display: "flex", flexDirection: "column", gap: 6, marginBottom: 14 }}>
                    <div>Assumed role: <span style={{ color: C.text, fontFamily: "monospace" }}>{verifyResult.assumed_arn}</span></div>
                    <div>GuardDuty: <span style={{ color: verifyResult.guardduty_enabled ? C.green : C.yellow }}>{verifyResult.guardduty_enabled ? "enabled" : "not detected"}</span></div>
                    {verifyResult.first_scan?.status === "queued" && <div style={{ color: C.accent }}>First scan queued — results will appear on the Overview page shortly.</div>}
                    {verifyResult.first_scan?.status === "completed" && <div style={{ color: C.accent }}>First scan complete — {verifyResult.first_scan.alerts_found} alert(s) found.</div>}
                  </div>
                  <button onClick={resetWizard} style={btnPrimary}>Done</button>
                </div>
              )}

              {verifyResult && !verifyResult.ok && (
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                    <div style={{
                      width: 36, height: 36, borderRadius: "50%", background: `${C.red}22`,
                      display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, color: C.red,
                    }}>✕</div>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 15 }}>Verification failed</div>
                      <div style={{ fontSize: 12, color: C.muted }}>{verifyResult.error}</div>
                    </div>
                  </div>
                  <div style={{ fontSize: 12, color: C.dim, marginBottom: 14 }}>
                    Double-check the trust policy's external ID and that the role name matches
                    what you entered, then retry.
                  </div>
                  <div style={{ display: "flex", gap: 10 }}>
                    <button onClick={() => handleVerify(connectedAccount.id)} style={btnPrimary}>Retry verification</button>
                    <button onClick={() => setStep(2)} style={btnSecondary}>Back to setup</button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function BillingPage({ authHeaders }) {
  const [sub, setSub]         = useState(null);
  const [plans, setPlans]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [upgrading, setUpgrading] = useState(null);
  const [portalLoading, setPortalLoading] = useState(false);
  const [error, setError]     = useState(null);
  const [msg, setMsg]         = useState(null);

  useEffect(() => {
    Promise.all([
      fetch(`${API_BASE}/billing/subscription`, { headers: authHeaders }).then(r => r.json()),
      fetch(`${API_BASE}/billing/plans`).then(r => r.json()),
    ]).then(([subData, plansData]) => {
      setSub(subData);
      setPlans(plansData.plans || []);
    }).catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  async function handleUpgrade(planTier) {
    setUpgrading(planTier); setMsg(null); setError(null);
    try {
      const res = await fetch(`${API_BASE}/billing/checkout`, {
        method: "POST",
        headers: { ...authHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({ plan: planTier }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Checkout failed");
      window.location.href = data.checkout_url;
    } catch (e) {
      setError(e.message);
    } finally {
      setUpgrading(null);
    }
  }

  async function handlePortal() {
    setPortalLoading(true); setError(null);
    try {
      const res = await fetch(`${API_BASE}/billing/portal`, {
        method: "POST", headers: authHeaders,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Portal failed");
      window.location.href = data.portal_url;
    } catch (e) {
      setError(e.message);
    } finally {
      setPortalLoading(false);
    }
  }

  const PLAN_ORDER = ["free", "starter", "pro", "enterprise"];
  const currentTier = sub?.plan?.tier || "free";
  const currentIdx  = PLAN_ORDER.indexOf(currentTier);

  const usagePct = sub
    ? Math.min(100, Math.round(
        (sub.usage.alerts_this_month / sub.plan.max_monthly_alerts) * 100
      ))
    : 0;

  const planHighlight = {
    free: "",
    starter: "",
    pro: C.accent,
    enterprise: C.purple,
  };

  if (loading) return (
    <div style={{ display:"flex", justifyContent:"center", padding:80 }}>
      <Spinner size={32}/>
    </div>
  );

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>

      {/* Header */}
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <div style={{ fontSize:20, fontWeight:700, marginBottom:4 }}>Billing & Plans</div>
          <div style={{ fontSize:12, color:C.muted }}>
            Manage your subscription, usage, and payment methods.
          </div>
        </div>
        {sub?.stripe_customer_id && (
          <button onClick={handlePortal} disabled={portalLoading} style={{
            display:"flex", alignItems:"center", gap:6,
            padding:"8px 16px", borderRadius:8, border:`1px solid ${C.cardBorder}`,
            background:C.card, color:C.text, fontSize:12, fontWeight:600,
            cursor:portalLoading ? "not-allowed":"pointer", opacity:portalLoading ? 0.7:1,
          }}>
            {portalLoading ? <Spinner size={12}/> : "⚙️"} Manage Subscription
          </button>
        )}
      </div>

      {error && <ErrorBanner message={error}/>}
      {msg   && (
        <div style={{ padding:"10px 14px", borderRadius:8, background:`${C.green}11`,
          border:`1px solid ${C.green}33`, fontSize:12, color:C.green }}>
          ✓ {msg}
        </div>
      )}

      {/* Current plan + usage */}
      <div style={{
        background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12,
        padding:"22px 24px",
      }}>
        <div style={{ fontSize:14, fontWeight:600, marginBottom:16 }}>Current Plan</div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:20 }}>

          {/* Plan details */}
          <div style={{
            padding:16, borderRadius:10, border:`1px solid ${C.cardBorder}`,
            background:C.hover,
          }}>
            <div style={{ fontSize:11, color:C.muted, marginBottom:6 }}>Plan</div>
            <div style={{ fontSize:22, fontWeight:700, marginBottom:2, textTransform:"capitalize" }}>
              {sub?.plan?.display_name || "Free"}
            </div>
            <div style={{ fontSize:12, color:C.muted }}>
              {sub?.plan?.price_usd_monthly === 0
                ? "Free forever"
                : `$${sub?.plan?.price_usd_monthly}/month`}
            </div>
            {sub?.stripe_subscription_status && (
              <div style={{
                marginTop:8, display:"inline-block", padding:"3px 8px",
                borderRadius:5, fontSize:11, fontWeight:600,
                background:sub.stripe_subscription_status === "active"
                  ? `${C.green}22` : `${C.yellow}22`,
                color:sub.stripe_subscription_status === "active" ? C.green : C.yellow,
              }}>
                {sub.stripe_subscription_status}
              </div>
            )}
          </div>

          {/* Alert usage */}
          <div style={{
            padding:16, borderRadius:10, border:`1px solid ${C.cardBorder}`,
            background:C.hover,
          }}>
            <div style={{ fontSize:11, color:C.muted, marginBottom:6 }}>Alerts This Month</div>
            <div style={{ fontSize:22, fontWeight:700, marginBottom:8 }}>
              {sub?.usage?.alerts_this_month?.toLocaleString() || 0}
              <span style={{ fontSize:13, color:C.muted, fontWeight:400 }}>
                {" "}/ {sub?.plan?.max_monthly_alerts?.toLocaleString()}
              </span>
            </div>
            <div style={{ height:6, background:`${C.cardBorder}`, borderRadius:3, overflow:"hidden" }}>
              <div style={{
                width:`${usagePct}%`, height:"100%", borderRadius:3,
                background: usagePct > 90 ? C.red : usagePct > 70 ? C.yellow : C.green,
                transition:"width 0.6s ease",
              }}/>
            </div>
            <div style={{ fontSize:11, color:C.dim, marginTop:6 }}>
              {usagePct}% of monthly limit used
            </div>
          </div>

          {/* AWS Accounts */}
          <div style={{
            padding:16, borderRadius:10, border:`1px solid ${C.cardBorder}`,
            background:C.hover,
          }}>
            <div style={{ fontSize:11, color:C.muted, marginBottom:6 }}>AWS Accounts</div>
            <div style={{ fontSize:22, fontWeight:700, marginBottom:2 }}>
              {sub?.usage?.aws_accounts_connected}
              <span style={{ fontSize:13, color:C.muted, fontWeight:400 }}>
                {" "}/ {sub?.plan?.max_aws_accounts}
              </span>
            </div>
            <div style={{ fontSize:12, color:C.dim }}>Connected accounts</div>
            <div style={{ fontSize:11, color:C.muted, marginTop:6 }}>
              Billing period: {sub?.usage?.period_start
                ? new Date(sub.usage.period_start).toLocaleDateString("en-US",{month:"short",day:"numeric"})
                : "—"} – {sub?.usage?.period_end
                ? new Date(sub.usage.period_end).toLocaleDateString("en-US",{month:"short",day:"numeric"})
                : "—"}
            </div>
          </div>

        </div>
      </div>

      {/* Plan cards */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:14 }}>
        {plans.map((plan, idx) => {
          const isCurrent  = plan.tier === currentTier;
          const isUpgrade  = PLAN_ORDER.indexOf(plan.tier) > currentIdx;
          const highlight  = planHighlight[plan.tier];
          const isPopular  = plan.tier === "pro";

          return (
            <div key={plan.tier} style={{
              background:C.card,
              border:`1px solid ${isCurrent ? C.accent : highlight || C.cardBorder}`,
              borderRadius:12, padding:"20px 18px",
              position:"relative",
              boxShadow: isCurrent ? `0 0 0 1px ${C.accent}44` : "none",
            }}>
              {isPopular && (
                <div style={{
                  position:"absolute", top:-10, left:"50%", transform:"translateX(-50%)",
                  background:C.accent, color:"#fff", fontSize:10, fontWeight:700,
                  padding:"3px 10px", borderRadius:10, whiteSpace:"nowrap",
                }}>MOST POPULAR</div>
              )}
              {isCurrent && (
                <div style={{
                  position:"absolute", top:-10, right:12,
                  background:C.green, color:"#000", fontSize:10, fontWeight:700,
                  padding:"3px 10px", borderRadius:10,
                }}>CURRENT</div>
              )}

              <div style={{ marginBottom:4, fontSize:14, fontWeight:700,
                color: highlight || C.text, textTransform:"capitalize" }}>
                {plan.display_name}
              </div>
              <div style={{ fontSize:26, fontWeight:800, marginBottom:2 }}>
                {plan.price_usd_monthly === 0
                  ? "Free"
                  : `$${plan.price_usd_monthly}`}
                {plan.price_usd_monthly > 0 && (
                  <span style={{ fontSize:13, color:C.muted, fontWeight:400 }}>/mo</span>
                )}
              </div>
              <div style={{ fontSize:11, color:C.muted, marginBottom:14 }}>
                {plan.max_aws_accounts === 999
                  ? "Unlimited accounts"
                  : `${plan.max_aws_accounts} AWS account${plan.max_aws_accounts > 1 ? "s" : ""}`}
                {" · "}
                {plan.max_monthly_alerts >= 999_999
                  ? "Unlimited alerts"
                  : `${plan.max_monthly_alerts.toLocaleString()} alerts/mo`}
              </div>

              <div style={{ borderTop:`1px solid ${C.cardBorder}`, paddingTop:14, marginBottom:16 }}>
                {plan.features.map(f => (
                  <div key={f} style={{
                    display:"flex", alignItems:"flex-start", gap:7,
                    marginBottom:7, fontSize:11, color:C.muted,
                  }}>
                    <span style={{ color:C.green, flexShrink:0 }}>✓</span>
                    {f}
                  </div>
                ))}
              </div>

              {isCurrent ? (
                <div style={{
                  width:"100%", padding:"9px", borderRadius:7,
                  background:`${C.accent}18`, border:`1px solid ${C.accent}44`,
                  color:C.accent, fontSize:12, fontWeight:600, textAlign:"center",
                }}>Current Plan</div>
              ) : isUpgrade ? (
                <button onClick={() => handleUpgrade(plan.tier)}
                  disabled={upgrading === plan.tier} style={{
                  width:"100%", padding:"9px", borderRadius:7, border:"none",
                  background: highlight || C.accent,
                  color:"#fff", fontSize:12, fontWeight:600, cursor:"pointer",
                  opacity: upgrading === plan.tier ? 0.7 : 1,
                  display:"flex", alignItems:"center", justifyContent:"center", gap:6,
                }}>
                  {upgrading === plan.tier && <Spinner size={12}/>}
                  Upgrade to {plan.display_name}
                </button>
              ) : (
                <div style={{
                  width:"100%", padding:"9px", borderRadius:7, textAlign:"center",
                  background:C.hover, color:C.dim, fontSize:12,
                }}>Lower tier</div>
              )}
            </div>
          );
        })}
      </div>

      {/* Feature comparison note */}
      <div style={{
        background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12,
        padding:"18px 24px",
      }}>
        <div style={{ fontSize:13, fontWeight:600, marginBottom:10 }}>Billing FAQ</div>
        {[
          ["When am I charged?", "Immediately on upgrade. Your card is billed monthly on the same date."],
          ["Can I cancel anytime?", "Yes. Cancel in the Stripe Customer Portal — you retain access until the period ends."],
          ["What happens if I exceed my alert limit?", "New alerts are rejected until the next billing period. Upgrade to avoid interruption."],
          ["Is there a free trial?", "The free tier is permanent. Pro plan offers a 14-day trial — contact us."],
        ].map(([q, a]) => (
          <div key={q} style={{ marginBottom:12 }}>
            <div style={{ fontSize:12, fontWeight:600, color:C.text, marginBottom:3 }}>{q}</div>
            <div style={{ fontSize:12, color:C.muted }}>{a}</div>
          </div>
        ))}
      </div>

    </div>
  );
}


// ─── Learning Page Component ──────────────────────────────────────────────────
const STAGE_CONFIG = {
  observing:             { color: "#475569", label: "Observing",         icon: "👁️"  },
  learning:              { color: "#3b82f6", label: "Learning",          icon: "📚" },
  candidate:             { color: "#f97316", label: "Candidate",         icon: "🎯" },
  pending_graduation:    { color: "#eab308", label: "Awaiting Approval", icon: "⏳" },
  autonomous:            { color: "#22c55e", label: "Autonomous",        icon: "⚡" },
  continuous_validation: { color: "#a855f7", label: "Under Review",      icon: "🔍" },
  disabled:              { color: "#ef4444", label: "Disabled",          icon: "🚫" },
};

function LifecycleBar({ status }) {
  const stages = ["observing","learning","candidate","pending_graduation","autonomous"];
  const idx = stages.indexOf(status);
  return (
    <div style={{ display:"flex", gap:3, marginTop:8, position:"relative", paddingTop:16 }}>
      {stages.map((s, i) => {
        const cfg = STAGE_CONFIG[s];
        const done = i < idx || status === "autonomous";
        const active = s === status;
        return (
          <div key={s} style={{ flex:1 }}>
            {active && (
              <div style={{
                position:"absolute", top:0,
                left:`calc(${(i/stages.length)*100}% + ${i*3}px)`,
                fontSize:9, color:cfg.color, fontWeight:700,
                whiteSpace:"nowrap",
              }}>{cfg.icon} {cfg.label}</div>
            )}
            <div style={{
              height:4, borderRadius:2,
              background: done || active ? cfg.color : C.cardBorder,
              opacity: active ? 1 : done ? 0.5 : 0.25,
              transition:"all 0.3s",
            }}/>
          </div>
        );
      })}
    </div>
  );
}

function PlaybookCard({ playbook, onApprove, onDisable, approving, disabling }) {
  const [expanded, setExpanded] = useState(false);
  const cfg = STAGE_CONFIG[playbook.status] || STAGE_CONFIG.disabled;
  const pct = Math.min(100, Math.round((playbook.instance_count / Math.max(playbook.learning_threshold,1)) * 100));
  return (
    <div style={{
      background:C.card, border:`1px solid ${C.cardBorder}`,
      borderLeft:`3px solid ${cfg.color}`, borderRadius:10, padding:"14px 16px", marginBottom:10,
    }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:5 }}>
            <span style={{ fontSize:15 }}>{cfg.icon}</span>
            <span style={{ fontSize:13, fontWeight:600 }}>{playbook.technique_name}</span>
            <span style={{
              fontSize:10, padding:"2px 7px", borderRadius:4, fontWeight:700,
              background:`${cfg.color}22`, color:cfg.color, border:`1px solid ${cfg.color}44`,
            }}>{cfg.label}</span>
            <span style={{ fontSize:10, color:C.dim }}>v{playbook.version}</span>
          </div>
          <div style={{ fontSize:11, color:C.muted, marginBottom:8, lineHeight:1.5 }}>
            {playbook.fingerprint_description}
          </div>
          <div style={{ display:"flex", gap:16, flexWrap:"wrap", marginBottom:8 }}>
            {[
              ["Action",     playbook.learned_action?.replace(/_/g," ")],
              ["Instances",  playbook.instance_count],
              ["Confidence", `${(playbook.confidence_score*100).toFixed(0)}%`],
              ["Trust",      `${(playbook.trust_score*100).toFixed(0)}%`],
              ["Successes",  playbook.successful_count],
              ["False +",    playbook.false_positive_count],
            ].map(([k,v]) => (
              <div key={k} style={{ fontSize:11 }}>
                <span style={{ color:C.dim }}>{k}: </span>
                <span style={{ color:C.text, fontWeight:600 }}>{v}</span>
              </div>
            ))}
          </div>
          <div>
            <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, color:C.dim, marginBottom:3 }}>
              <span>Progress ({playbook.instance_count}/{playbook.learning_threshold} instances)</span>
              <span>{pct}%</span>
            </div>
            <div style={{ height:4, background:C.hover, borderRadius:2, overflow:"hidden" }}>
              <div style={{
                width:`${pct}%`, height:"100%", borderRadius:2,
                background:`linear-gradient(90deg,${cfg.color}88,${cfg.color})`,
              }}/>
            </div>
          </div>
          <LifecycleBar status={playbook.status}/>
          {playbook.status === "pending_graduation" && (
            <div style={{
              marginTop:10, padding:"8px 12px", borderRadius:6,
              background:`${C.yellow}11`, border:`1px solid ${C.yellow}33`,
              fontSize:11, color:C.yellow,
            }}>
              ⏳ Ready for graduation — {playbook.instance_count} confirmed instances,
              confidence {(playbook.confidence_score*100).toFixed(0)}%,
              trust {(playbook.trust_score*100).toFixed(0)}%.
              Approve below to enable autonomous execution.
            </div>
          )}
          {playbook.status === "autonomous" && (
            <div style={{
              marginTop:10, padding:"8px 12px", borderRadius:6,
              background:`${C.green}11`, border:`1px solid ${C.green}33`,
              fontSize:11, color:C.green,
            }}>
              ⚡ Autonomous — handling this pattern automatically.
              {playbook.last_executed_at && ` Last executed: ${timeAgo(playbook.last_executed_at)}.`}
            </div>
          )}
          {playbook.status === "continuous_validation" && (
            <div style={{
              marginTop:10, padding:"8px 12px", borderRadius:6,
              background:`${C.purple}11`, border:`1px solid ${C.purple}33`,
              fontSize:11, color:C.purple,
            }}>
              🔍 Under review — trust dropped. Re-evaluating before restoring autonomous mode.
            </div>
          )}
        </div>
        <div style={{ display:"flex", flexDirection:"column", gap:6, marginLeft:14, flexShrink:0 }}>
          {playbook.status === "pending_graduation" && (
            <button onClick={() => onApprove(playbook.id)} disabled={approving===playbook.id} style={{
              padding:"6px 12px", borderRadius:6, border:"none",
              background:C.green, color:"#000", fontSize:11, fontWeight:700,
              cursor:approving===playbook.id?"not-allowed":"pointer",
              opacity:approving===playbook.id?0.7:1,
              display:"flex", alignItems:"center", gap:5,
            }}>
              {approving===playbook.id ? <Spinner size={10}/> : "✓"} Approve
            </button>
          )}
          {!["disabled","observing"].includes(playbook.status) && (
            <button onClick={() => onDisable(playbook.id)} disabled={disabling===playbook.id} style={{
              padding:"6px 12px", borderRadius:6, border:`1px solid ${C.cardBorder}`,
              background:"transparent", color:C.muted, fontSize:11, cursor:"pointer",
            }}>Disable</button>
          )}
          <button onClick={() => setExpanded(!expanded)} style={{
            padding:"6px 12px", borderRadius:6, border:`1px solid ${C.cardBorder}`,
            background:"transparent", color:C.muted, fontSize:11, cursor:"pointer",
          }}>{expanded ? "Hide" : "Details"}</button>
        </div>
      </div>
      {expanded && playbook.observations?.length > 0 && (
        <div style={{ marginTop:12, borderTop:`1px solid ${C.cardBorder}`, paddingTop:12 }}>
          <div style={{ fontSize:11, color:C.dim, marginBottom:8, fontWeight:600 }}>
            OBSERVATION HISTORY ({playbook.observations.length})
          </div>
          {[...playbook.observations].reverse().slice(0,5).map(obs => (
            <div key={obs.id} style={{
              display:"flex", justifyContent:"space-between", alignItems:"center",
              padding:"7px 10px", borderRadius:6, marginBottom:4,
              background: obs.outcome==="success" ? `${C.green}0a` : `${C.red}0a`,
              border:`1px solid ${obs.outcome==="success" ? C.green : C.red}22`,
            }}>
              <div style={{ fontSize:11 }}>
                <span style={{ color:obs.was_autonomous?C.purple:C.accent, fontWeight:600 }}>
                  {obs.was_autonomous ? "⚡ Auto" : "👤 Analyst"}
                </span>
                <span style={{ color:C.muted, marginLeft:8 }}>{obs.analyst_action?.replace(/_/g," ")}</span>
                {obs.analyst_notes && (
                  <span style={{ color:C.dim, marginLeft:8, fontStyle:"italic" }}>
                    "{obs.analyst_notes.slice(0,60)}{obs.analyst_notes.length>60?"…":""}"
                  </span>
                )}
              </div>
              <div style={{ display:"flex", alignItems:"center", gap:8, flexShrink:0 }}>
                <span style={{ fontSize:10, fontWeight:700,
                  color:obs.outcome==="success"?C.green:C.red }}>
                  {obs.outcome==="success" ? "✓ Success" : "✗ FP"}
                </span>
                <span style={{ fontSize:10, color:C.dim }}>{timeAgo(obs.created_at)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function LearningPage({ authHeaders }) {
  const [summary,   setSummary]   = useState(null);
  const [playbooks, setPlaybooks] = useState([]);
  const [settings,  setSettings]  = useState(null);
  const [loading,   setLoading]   = useState(true);
  const [filter,    setFilter]    = useState("all");
  const [approving, setApproving] = useState(null);
  const [disabling, setDisabling] = useState(null);
  const [error,     setError]     = useState(null);
  const [msg,       setMsg]       = useState(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [sumD, pbD, setD] = await Promise.all([
        fetch(`${API_BASE}/learning/summary`,   { headers:authHeaders }).then(r=>r.json()),
        fetch(`${API_BASE}/learning/playbooks`, { headers:authHeaders }).then(r=>r.json()),
        fetch(`${API_BASE}/learning/settings`,  { headers:authHeaders }).then(r=>r.json()),
      ]);
      setSummary(sumD);
      setPlaybooks(Array.isArray(pbD) ? pbD : []);
      setSettings(setD);
    } catch(e) { setError(e.message); }
    finally    { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  async function handleApprove(memoryId) {
    setApproving(memoryId); setMsg(null); setError(null);
    try {
      const r = await fetch(`${API_BASE}/learning/playbooks/${memoryId}/approve`, {
        method:"POST",
        headers:{...authHeaders,"Content-Type":"application/json"},
        body:JSON.stringify({ confirmed:true, notes:null }),
      });
      if (!r.ok) throw new Error((await r.json()).detail || "Approval failed");
      setMsg("✓ Playbook approved — autonomous execution enabled.");
      load();
    } catch(e) { setError(e.message); }
    finally    { setApproving(null); }
  }

  async function handleDisable(memoryId) {
    setDisabling(memoryId); setMsg(null); setError(null);
    try {
      const r = await fetch(`${API_BASE}/learning/playbooks/${memoryId}/disable`, {
        method:"POST",
        headers:{...authHeaders,"Content-Type":"application/json"},
        body:JSON.stringify({ reason:"Disabled from dashboard" }),
      });
      if (!r.ok) throw new Error((await r.json()).detail || "Disable failed");
      setMsg("Playbook disabled."); load();
    } catch(e) { setError(e.message); }
    finally    { setDisabling(null); }
  }

  const stageFilters = [
    ["all","All",null],
    ["pending_graduation","Needs Approval",C.yellow],
    ["autonomous","Autonomous",C.green],
    ["learning","Learning",C.accent],
    ["candidate","Candidate",C.orange],
    ["observing","Observing",C.dim],
    ["continuous_validation","Under Review",C.purple],
    ["disabled","Disabled",C.red],
  ];
  const filtered = filter==="all" ? playbooks : playbooks.filter(p=>p.status===filter);

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div>
        <div style={{ fontSize:20, fontWeight:700, marginBottom:4 }}>Adaptive Playbook Learning</div>
        <div style={{ fontSize:12, color:C.muted }}>
          Cloud Guardian learns from analyst decisions and autonomously handles recurring attack
          patterns after reaching your confidence threshold and receiving approval.
        </div>
      </div>

      {error && <ErrorBanner message={error}/>}
      {msg && (
        <div style={{ padding:"10px 14px", borderRadius:8, background:`${C.green}11`,
          border:`1px solid ${C.green}33`, fontSize:12, color:C.green }}>{msg}</div>
      )}

      {summary && (
        <div style={{ display:"grid", gridTemplateColumns:"repeat(7,1fr)", gap:10 }}>
          {[
            ["Observing",        summary.observing,             C.dim   ],
            ["Learning",         summary.learning,              C.accent],
            ["Candidate",        summary.candidate,             C.orange],
            ["Needs Approval",   summary.pending_graduation,    C.yellow],
            ["Autonomous",       summary.autonomous,            C.green ],
            ["Under Review",     summary.continuous_validation, C.purple],
            ["Auto-Executions",  summary.total_auto_executions, C.green ],
          ].map(([label,value,color]) => (
            <div key={label} style={{
              background:C.card, border:`1px solid ${C.cardBorder}`,
              borderTop:`2px solid ${color}`, borderRadius:10, padding:"12px 14px",
            }}>
              <div style={{ fontSize:22, fontWeight:700, color }}>{value}</div>
              <div style={{ fontSize:10, color:C.muted, marginTop:2 }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      {summary?.pending_graduation > 0 && (
        <div style={{
          background:`${C.yellow}08`, border:`1px solid ${C.yellow}44`,
          borderRadius:10, padding:"14px 18px",
          display:"flex", justifyContent:"space-between", alignItems:"center",
        }}>
          <div>
            <div style={{ fontSize:13, fontWeight:600, color:C.yellow, marginBottom:2 }}>
              ⏳ {summary.pending_graduation} playbook{summary.pending_graduation>1?"s":""} awaiting approval
            </div>
            <div style={{ fontSize:11, color:C.muted }}>
              These patterns have been confirmed enough times to go autonomous. Review and approve.
            </div>
          </div>
          <button onClick={() => setFilter("pending_graduation")} style={{
            padding:"7px 14px", borderRadius:7, border:`1px solid ${C.yellow}`,
            background:`${C.yellow}22`, color:C.yellow,
            fontSize:12, fontWeight:600, cursor:"pointer", flexShrink:0,
          }}>Review Queue</button>
        </div>
      )}

      {settings && (
        <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:10, padding:"14px 18px" }}>
          <div style={{ fontSize:13, fontWeight:600, marginBottom:10 }}>Learning Configuration</div>
          <div style={{ display:"flex", gap:24, flexWrap:"wrap" }}>
            {[
              ["Observe Threshold",   settings.observe_threshold,   "sightings before learning starts"],
              ["Candidate Threshold", settings.candidate_threshold, "observations to become candidate"],
              ["Learning Threshold",  settings.learning_threshold,  "confirmed instances to graduate"],
              ["Confidence Required", `${(settings.confidence_threshold*100).toFixed(0)}%`, "minimum confidence"],
              ["Trust Required",      `${(settings.trust_threshold*100).toFixed(0)}%`,      "minimum trust score"],
            ].map(([label,value,desc]) => (
              <div key={label}>
                <div style={{ fontSize:20, fontWeight:700, color:C.accent }}>{value}</div>
                <div style={{ fontSize:11, fontWeight:600, color:C.text }}>{label}</div>
                <div style={{ fontSize:10, color:C.dim }}>{desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12 }}>
          <div style={{ fontSize:14, fontWeight:600 }}>
            Learned Playbooks
            <span style={{ color:C.muted, fontWeight:400, marginLeft:8 }}>
              ({filtered.length} of {playbooks.length})
            </span>
          </div>
          <div style={{ display:"flex", gap:5, flexWrap:"wrap" }}>
            {stageFilters.map(([key,label,color]) => (
              <button key={key} onClick={() => setFilter(key)} style={{
                padding:"4px 10px", borderRadius:20, fontSize:11, cursor:"pointer",
                border:`1px solid ${filter===key ? (color||C.accent) : C.cardBorder}`,
                background: filter===key ? `${(color||C.accent)}22` : "transparent",
                color: filter===key ? (color||C.accent) : C.muted,
                fontWeight: filter===key ? 600 : 400,
              }}>{label}</button>
            ))}
          </div>
        </div>

        {loading ? (
          <div style={{ display:"flex", justifyContent:"center", padding:48 }}><Spinner size={28}/></div>
        ) : filtered.length === 0 ? (
          <div style={{
            textAlign:"center", padding:"48px 0", color:C.dim,
            background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12,
          }}>
            <div style={{ fontSize:48, marginBottom:12 }}>🧠</div>
            <div style={{ fontSize:14, fontWeight:600, color:C.muted, marginBottom:6 }}>
              {filter==="all" ? "No learned playbooks yet" : `No ${filter} playbooks`}
            </div>
            <div style={{ fontSize:12 }}>
              {filter==="all"
                ? "The system learns as analysts approve and dismiss incidents. Run a scan, respond to alerts, and the system will start building playbook memory."
                : `No playbooks are currently in the ${filter} stage.`}
            </div>
          </div>
        ) : filtered.map(pb => (
          <PlaybookCard key={pb.id} playbook={pb}
            onApprove={handleApprove} onDisable={handleDisable}
            approving={approving} disabling={disabling}/>
        ))}
      </div>

      <div style={{ background:C.card, border:`1px solid ${C.cardBorder}`, borderRadius:12, padding:"16px 20px" }}>
        <div style={{ fontSize:13, fontWeight:600, marginBottom:14 }}>7-Stage Learning Lifecycle</div>
        <div style={{ display:"flex", gap:0 }}>
          {Object.entries(STAGE_CONFIG).filter(([k])=>k!=="disabled").map(([key,cfg],i,arr) => (
            <div key={key} style={{ flex:1, textAlign:"center", position:"relative" }}>
              <div style={{ fontSize:20, marginBottom:4 }}>{cfg.icon}</div>
              <div style={{ fontSize:10, fontWeight:700, color:cfg.color }}>{cfg.label}</div>
              <div style={{ fontSize:9, color:C.dim, marginTop:3, lineHeight:1.3, padding:"0 2px" }}>
                {["1-2 sightings","Analyst confirms","Building trust","Admin reviews","Auto-executes","Re-evaluating"][i]}
              </div>
              {i < arr.length-1 && (
                <div style={{
                  position:"absolute", right:-6, top:10,
                  fontSize:14, color:C.dim,
                }}>›</div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [authed, setAuthed] = useState(false);
  return authed
    ? <Dashboard onLogout={() => { setToken(null); setAuthed(false); }}/>
    : <LoginScreen onLogin={() => setAuthed(true)}/>;
}

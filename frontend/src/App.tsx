import { Component, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { ErrorInfo, ReactNode } from "react";
import "./App.css";

// --- Metric type ---

type Metric = {
  value: number | null
  supported: boolean
  unit?: string
}

function metricValue(
  metric: Metric | number | null | undefined
): number | null {
  if (metric == null) return null
  if (typeof metric === "number") return metric
  return metric.supported && typeof metric.value === "number"
    ? metric.value
    : null
}

interface MetricCardProps {
  title: string
  value: string | number
  unit?: string
  subtitle?: string
  icon?: string
  color?: string
  status?: "ok" | "warning" | "critical"
  progress?: number
}

interface StorageDisk {
  display_name: string;
  mount: string;
  device: string | null;
  parent_device?: string | null;
  fstype: string | null;
  options?: string;
  read_only?: boolean;
  uuid?: string | null;
  label?: string | null;
  model?: string | null;
  transport?: string | null;
  rotational?: boolean | null;
  kind?: "internal" | "external" | "virtual" | string;
  health?: "healthy" | "warning" | "critical" | string;
  total_bytes: number;
  used_bytes: number;
  free_bytes: number;
  percent: number;
}

interface WebSocketData {
  cpu: {
    percent: Metric;
    per_core: Metric[];
    cores_logical: number;
    cores_physical: number;
    load_average: { "1m": number; "5m": number; "1m_per_core": number };
    frequency_mhz: { current: Metric; min: Metric; max: Metric };
  };
  memory: {
    ram: { percent: Metric; available_bytes: number; total_bytes: number; used_bytes: number };
    swap: { percent: Metric; total_bytes: number; used_bytes: number; free_bytes: number };
  };
  gpu: {
    index: number;
    name: string | null;
    uuid: string | null;
    driver_version: string;
    persistence_mode: string;
    utilization: Metric;
    memory: { total_bytes: number; used_bytes: number; free_bytes: number; percent: Metric };
    temperature: Metric;
    power_draw: Metric;
    power_limit: Metric;
    fan_speed_pct: Metric;
    clocks: { graphics_mhz: Metric; memory_mhz: Metric; max_graphics_mhz: Metric; max_memory_mhz: Metric };
    available: boolean;
  };
  temperature: {
    cpu: {
      package_c: number;
      supported: boolean;
      source: string;
      critical_c: number;
      cores: { label: string; celsius: number }[];
    };
  };
  fan: {
    available: boolean;
    read_only: boolean;
    fan: { state: string; on: boolean; last_change_at: number | null; poll_age_seconds: number };
    controller: { unit: string; active: boolean; status: string };
    tuya: { state: string; secrets: Record<string, unknown> };
    thresholds: { on_temp_c: number; off_temp_c: number; min_on_seconds?: number };
    cpu_temp: number;
    automation?: { mode: string; reason?: string; manual_control_available?: boolean; note?: string };
  };
  network: {
    active_interface: string;
    lan: { interface: string; kind: string; state: string; address: string; rx_bytes_per_sec: number; tx_bytes_per_sec: number };
    wifi?: { interface: string; kind: string; state: string; address: string; rx_bytes_per_sec: number; tx_bytes_per_sec: number };
  };
  storage_external: Record<string, unknown>;
  storage?: { available: boolean; disks: StorageDisk[]; count: number; internal_count?: number; external_count?: number };
  processes: {
    top_cpu: any[];
    top_ram: any[];
    total_processes: number;
  };
  gpu_processes: {
    available: boolean;
    processes: any[];
    total: number;
    per_process_utilization: Metric;
  };
  services: {
    available: boolean;
    services: any[];
    counts: { total: number; running: number; failed: number };
  };
  containers?: {
    available: boolean;
    containers: any[];
    count: number;
  };
  health: {
    status: string;
    reasons?: string[];
    warning_count: number;
    critical_count: number;
  };
  meta?: {
    host: string;
    generated_at: number;
    generated_at_iso: string;
    uptime_seconds: number;
    health_status: string;
  };
  timestamp?: number;
}

interface StorageExternal {
  name: string;
  health: string;
  connected: boolean;
  mounted: boolean;
  current_device: string | null;
  mountpoint: string | null;
  filesystem: string | null;
  mount_mode: string | null;
  capacity_bytes: number;
  used_bytes: number;
  free_bytes: number;
  percent_used: number;
  abbreviated_uuid: string;
  filesystem_uuid: string;
  last_seen_at?: number | null;
  connected_since?: number | null;
  transport: string;
  available?: boolean;
}

interface StorageEvent {
  id: number;
  timestamp_utc: string;
  event_type: string;
  device_path: string | null;
  previous_device_path: string | null;
  severity: string;
  reason: string | null;
  diagnosis: string | null;
  details_json?: Record<string, unknown> | null;
  filesystem_uuid?: string | null;
  confidence?: string | null;
  mountpoint?: string | null;
}

// --- Helpers ---

function formatBytes(bytes: number | null | undefined): string {
  const b = bytes ?? 0
  if (b < 1024) return `${b} B`
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = b;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

function formatGiB(bytes: number | null | undefined): string {
  const b = bytes ?? 0
  return `${(b / 1024**3).toFixed(1)} GiB`
}

function formatPercent(value: number | null | undefined): string {
  const v = value ?? 0
  return `${v.toFixed(1)}%`
}

function utcToLocale(utcString: string): string {
  if (!utcString) return "—";
  try {
    const d = new Date(utcString);
    return d.toLocaleString("id-ID", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZone: "Asia/Jakarta",
    });
  } catch {
    return utcString;
  }
}

function healthColor(health: string): string {
  const map: Record<string, string> = {
    HEALTHY: "text-green-400",
    HEALTHY_HEART: "text-green-400",
    HEALTHY_FULL: "text-green-400",
    CONNECTED_UNMOUNTED: "text-amber-400",
    DISCONNECTED: "text-red-400",
    WRONG_DEVICE: "text-red-400",
    READ_ONLY: "text-amber-400",
    IO_ERROR: "text-red-400",
    FILESYSTEM_ERROR: "text-red-400",
    WARNING: "text-amber-400",
    CRITICAL: "text-red-400",
    healthy: "text-green-400",
    warning: "text-amber-400",
    critical: "text-red-400",
  };
  return map[health] || "text-slate-400";
}

function healthDot(health: string): string {
  const map: Record<string, string> = {
    HEALTHY: "bg-green-400 shadow-green-400/50",
    HEALTHY_FULL: "bg-green-400 shadow-green-400/50",
    CONNECTED_UNMOUNTED: "bg-amber-400 shadow-amber-400/50",
    DISCONNECTED: "bg-red-400 shadow-red-400/50",
    WRONG_DEVICE: "bg-red-400 shadow-red-400/50",
    READ_ONLY: "bg-amber-400 shadow-amber-400/50",
    IO_ERROR: "bg-red-400 shadow-red-400/50",
    FILESYSTEM_ERROR: "bg-red-400 shadow-red-400/50",
    healthy: "bg-green-400 shadow-green-400/50",
    warning: "bg-amber-400 shadow-amber-400/50",
    critical: "bg-red-400 shadow-red-400/50",
  };
  return map[health] || "bg-slate-400 shadow-slate-400/50";
}

// --- UseWebSocket hook ---

function useWebSocket(url: string): { data: WebSocketData | null; connected: boolean; error: string | null } {
  const [data, setData] = useState<WebSocketData | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!url) {
      setConnected(false);
      setError(null);
      setData(null);
      return;
    }
    const ws = new WebSocket(url);

    ws.onopen = () => {
      setConnected(true);
      setError(null);
    };

    ws.onmessage = (event) => {
      try {
        setData(JSON.parse(event.data));
      } catch {
        setError("Parse error");
      }
    };

    ws.onerror = () => {
      setError("Connection error");
    };

    ws.onclose = () => {
      setConnected(false);
    };

    return () => ws.close();
  }, [url]);

  return { data, connected, error };
}

// --- MetricCard ---

const MetricCard: React.FC<MetricCardProps> = ({ title, value, unit, subtitle, icon, color, status, progress }) => (
  <div className={`summary-card ${status ? `status-${status}` : ""}`}>
    {icon && <div className={`metric-icon ${color || ""}`}>{icon}</div>}
    <div className="metric-label">{title}</div>
    <div className="metric-value">
      {value}
      {unit && <span className="metric-unit">{unit}</span>}
    </div>
    {subtitle && <div className="metric-secondary">{subtitle}</div>}
    {progress !== undefined && (
      <div className="progress-bar">
        <div
          className={`progress-fill ${status || "ok"}`}
          style={{ width: `${Math.min(progress, 100)}%` }}
        />
      </div>
    )}
  </div>
);

// --- TopCards ---

const TopCards: React.FC<{ data: WebSocketData | null }> = ({ data }) => {
  if (!data) {
    return (
      <div className="summary-grid">
        {[...Array(9)].map((_, i) => (
          <div key={i} className="summary-card animate-pulse-slow opacity-50">
            <div className="metric-label">Loading…</div>
            <div className="metric-value">—</div>
          </div>
        ))}
      </div>
    );
  }

  const cpuPct = metricValue(data.cpu?.percent)
  const gpuUtil = metricValue(data.gpu?.utilization)
  const ramUsed = data.memory?.ram?.used_bytes ?? 0
  const ramTotal = data.memory?.ram?.total_bytes ?? 0
  const ramAvailable = data.memory?.ram?.available_bytes ?? 0
  const swapUsed = data.memory?.swap?.used_bytes ?? 0
  const swapTotal = data.memory?.swap?.total_bytes ?? 0
  const swapFree = data.memory?.swap?.free_bytes ?? 0
  const gpuUsed = data.gpu?.memory?.used_bytes ?? 0
  const gpuTotal = data.gpu?.memory?.total_bytes ?? 0
  const gpuFree = data.gpu?.memory?.free_bytes ?? 0
  const netRx = data.network?.lan?.rx_bytes_per_sec ?? 0
  const netTx = data.network?.lan?.tx_bytes_per_sec ?? 0
  const ramPct = metricValue(data.memory?.ram?.percent)
  const swapPct = metricValue(data.memory?.swap?.percent)
  const vramPct = metricValue(data.gpu?.memory?.percent)
  const cpuTemp = data.temperature?.cpu?.package_c ?? null
  const gpuTemp = metricValue(data.gpu?.temperature)
  const fanOn = data.fan?.fan?.on ?? false

  const ramStatus = ramPct !== null && ramPct >= 95 ? "critical" : ramPct !== null && ramPct >= 85 ? "warning" : "ok"
  const swapStatus = swapPct !== null && swapPct >= 90 ? "critical" : swapPct !== null && swapPct >= 75 ? "warning" : "ok"

  return (
    <div className="summary-grid">
      <MetricCard
        title="CPU"
        value={cpuPct !== null ? `${cpuPct.toFixed(1)}` : "N/A"}
        unit={cpuPct !== null ? "%" : undefined}
        subtitle={cpuTemp !== null ? `${cpuTemp.toFixed(0)}°C` : undefined}
        icon="🖥️"
        color="text-cyan-400"
        status={cpuPct !== null && cpuPct > 90 ? "critical" : cpuPct !== null && cpuPct > 70 ? "warning" : "ok"}
      />
      <MetricCard
        title="GPU"
        value={gpuUtil !== null ? `${gpuUtil.toFixed(0)}` : "N/A"}
        unit={gpuUtil !== null ? "%" : undefined}
        subtitle={gpuTemp !== null ? `${gpuTemp.toFixed(0)}°C` : undefined}
        icon="🎮"
        color="text-purple-400"
      />
      <MetricCard
        title="RAM"
        value={`${formatGiB(ramUsed)} / ${formatGiB(ramTotal)}`}
        subtitle={`Available ${formatGiB(ramAvailable)}`}
        icon="🧠"
        color="text-green-400"
        status={ramStatus}
        progress={ramPct ?? undefined}
      />
      <MetricCard
        title="SWAP"
        value={`${formatGiB(swapUsed)} / ${formatGiB(swapTotal)}`}
        subtitle={`Free ${formatGiB(swapFree)}`}
        icon="💾"
        color="text-amber-400"
        status={swapStatus}
        progress={swapPct ?? undefined}
      />
      <MetricCard
        title="VRAM"
        value={`${formatGiB(gpuUsed)} / ${formatGiB(gpuTotal)}`}
        subtitle={`Free ${formatBytes(gpuFree)}`}
        icon="💾"
        color="text-purple-400"
        status={vramPct !== null && vramPct > 90 ? "critical" : vramPct !== null && vramPct > 75 ? "warning" : "ok"}
        progress={vramPct ?? undefined}
      />
      <MetricCard
        title="Network"
        value={`↓ ${(netRx / 1024).toFixed(1)} KB/s`}
        subtitle={`↑ ${(netTx / 1024).toFixed(1)} KB/s`}
        icon="🌐"
        color="text-cyan-400"
      />
      <MetricCard
        title="CPU Temp"
        value={cpuTemp !== null ? `${cpuTemp.toFixed(0)}` : "N/A"}
        unit={cpuTemp !== null ? "°C" : undefined}
        subtitle={cpuTemp !== null ? (cpuTemp >= 70 ? "Hot" : cpuTemp >= 50 ? "Elevated" : "Normal") : undefined}
        icon="🌡️"
        color="text-amber-400"
        status={cpuTemp !== null && cpuTemp >= 70 ? "critical" : cpuTemp !== null && cpuTemp > 50 ? "warning" : "ok"}
      />
      <MetricCard
        title="GPU Temp"
        value={gpuTemp !== null ? `${gpuTemp.toFixed(0)}` : "N/A"}
        unit={gpuTemp !== null ? "°C" : undefined}
        subtitle={gpuTemp !== null ? (gpuTemp >= 75 ? "Hot" : "Normal") : undefined}
        icon="🔥"
        color="text-purple-400"
        status={gpuTemp !== null && gpuTemp >= 75 ? "critical" : gpuTemp !== null && gpuTemp > 60 ? "warning" : "ok"}
      />
      <MetricCard
        title="Fan"
        value={fanOn ? "ON" : "OFF"}
        subtitle="AUTO"
        icon="🌀"
        color="text-cyan-400"
        status={fanOn ? "ok" : "warning"}
      />
    </div>
  );
};

// --- AcasisStorageCard ---

const AcasisStorageCard: React.FC<{ data: StorageExternal | null; onEventsClick: () => void }> = ({
  data,
  onEventsClick,
}) => {
  if (!data || !data.available) {
    return (
      <div className="panel">
        <div className="panel-header">
          <h2 className="panel-title">{data?.name || "External Storage"}</h2>
        </div>
        <div className="panel-body">
          <div className="events-empty">
            <div className={`text-2xl mb-2 ${healthDot("DISCONNECTED")} overflow-hidden border-2 border-transparent rounded-full`}></div>
            <p className="text-red-400">Storage Unavailable</p>
            <p className="text-slate-500 text-sm mt-2">Waiting for storage discovery…</p>
          </div>
        </div>
      </div>
    );
  }

  const pct = data.percent_used ?? 0;
  const capacity = data.capacity_bytes ?? 0;

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="storage-header">
          <h2 className="panel-title">{data?.name || "External Storage"}</h2>
          <div className="storage-health">
            <div className={`storage-health-dot ${data.health === "HEALTHY" ? "healthy" : data.health === "WARNING" || data.health === "READ_ONLY" ? "warning" : "critical"}`}></div>
            <span className={`text-sm font-medium ${healthColor(data.health)}`}>
              {data.health.toUpperCase().replace("_", " ")}
            </span>
          </div>
        </div>
      </div>
      <div className="panel-body">
        <div className="storage-capacity">
          {formatBytes(capacity)} · {formatPercent(pct)}
        </div>

        <div className="storage-progress">
          <div className="progress-bar">
            <div
              className={`progress-fill ${pct > 90 ? "critical" : pct > 75 ? "warning" : "ok"}`}
              style={{ width: `${Math.min(pct, 100)}%` }}
            />
          </div>
        </div>

        <div className="storage-stats">
          <div className="storage-stat">
            <span className="storage-stat-label">Used</span>
            <span className="storage-stat-value">{formatBytes(data.used_bytes ?? 0)}</span>
          </div>
          <div className="storage-stat">
            <span className="storage-stat-label">Free</span>
            <span className="storage-stat-value">{formatBytes(data.free_bytes ?? 0)}</span>
          </div>
        </div>

        <div className="storage-info">
          <div className="storage-info-row">
            <span className="storage-info-label">Mount</span>
            <span className="storage-info-value">{data.mountpoint || "—"}</span>
          </div>
          <div className="storage-info-row">
            <span className="storage-info-label">Filesystem</span>
            <span className="storage-info-value">{data.filesystem || "—"} · {data.mount_mode?.includes("ro") ? "RO" : "RW"}</span>
          </div>
          <div className="storage-info-row">
            <span className="storage-info-label">Transport</span>
            <span className="storage-info-value">{data.transport?.toUpperCase() || "—"}</span>
          </div>
          <div className="storage-info-row">
            <span className="storage-info-label">UUID</span>
            <span className="storage-info-value">{data.abbreviated_uuid || "—"}</span>
          </div>
          <div className="storage-info-row">
            <span className="storage-info-label">Device</span>
            <span className="storage-info-value">{data.current_device || "—"}</span>
          </div>
        </div>

        <div className="storage-actions">
          <button onClick={onEventsClick}>
            View Event Log →
          </button>
        </div>
      </div>
    </div>
  );
};

// --- ProcessTable ---

const ProcessTable: React.FC<{ title: string; processes: any[]; cpuSupported: boolean; ramMode?: boolean }> = ({
  title,
  processes,
  ramMode,
}) => {
  return (
    <div className="panel">
      <div className="panel-header">
        <h3 className="panel-title">{title}</h3>
      </div>
      <div className="panel-body">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Application</th>
                <th className="text-right">PID</th>
                {ramMode ? (
                  <>
                    <th className="text-right">RAM</th>
                    <th className="text-right">RAM %</th>
                    <th className="text-right">CPU</th>
                  </>
                ) : (
                  <>
                    <th className="text-right">CPU</th>
                    <th className="text-right">RAM</th>
                    <th className="text-right">Runtime</th>
                  </>
                )}
              </tr>
            </thead>
            <tbody>
              {processes.slice(0, 10).map((p, i) => (
                <tr key={p.pid || i}>
                  <td className="truncate" style={{ maxWidth: "120px" }}>{p.display_name || p.name || "—"}</td>
                  <td className="text-right" style={{ fontFamily: "monospace", color: "var(--text-muted)" }}>{p.pid || "—"}</td>
                  {ramMode ? (
                    <>
                      <td className="text-right" style={{ fontFamily: "monospace" }}>{formatBytes(p.ram_bytes ?? 0)}</td>
                      <td className="text-right" style={{ color: "var(--cyan)" }}>{((p.ram_percent ?? 0) as number).toFixed(1)}</td>
                      <td className="text-right" style={{ color: "var(--text-muted)" }}>{((p.cpu_percent ?? 0) as number).toFixed(1)}</td>
                    </>
                  ) : (
                    <>
                      <td className="text-right" style={{ color: "var(--cyan)" }}>{((p.cpu_percent ?? 0) as number).toFixed(1)}</td>
                      <td className="text-right" style={{ fontFamily: "monospace", color: "var(--text-muted)" }}>{formatBytes(p.ram_bytes ?? 0)}</td>
                      <td className="text-right" style={{ color: "var(--text-muted)" }}>{p.runtime_human || "—"}</td>
                    </>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// --- GPUProcessTable ---

const GPUProcessTable: React.FC<{ processes: any[] }> = ({ processes }) => {
  return (
    <div className="panel">
      <div className="panel-header">
        <h3 className="panel-title">GPU Processes</h3>
      </div>
      <div className="panel-body">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Application</th>
                <th className="text-right">PID</th>
                <th className="text-right">VRAM</th>
                <th className="text-right">GPU</th>
                <th className="text-right">CPU</th>
                <th className="text-right">RAM</th>
              </tr>
            </thead>
            <tbody>
              {processes.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center" style={{ padding: "12px", color: "var(--text-muted)" }}>No GPU processes</td>
                </tr>
              ) : (
                processes.slice(0, 10).map((p, i) => (
                  <tr key={p.pid || i}>
                    <td className="truncate" style={{ maxWidth: "120px" }}>{p.display_name || p.name || "—"}</td>
                    <td className="text-right" style={{ fontFamily: "monospace", color: "var(--text-muted)" }}>{p.pid || "—"}</td>
                    <td className="text-right" style={{ fontFamily: "monospace", color: "var(--purple)" }}>{formatBytes(p.vram_bytes ?? 0)}</td>
                    <td className="text-right" style={{ color: "var(--text-muted)" }}>N/A</td>
                    <td className="text-right" style={{ color: "var(--text-muted)" }}>{((p.cpu_percent ?? 0) as number).toFixed(1)}</td>
                    <td className="text-right" style={{ fontFamily: "monospace", color: "var(--text-muted)" }}>{formatBytes(p.ram_bytes ?? 0)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// --- NetworkChart ---

const NetworkChart: React.FC<{ data: WebSocketData | null }> = ({ data }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const valuesRef = useRef<{ rx: number; tx: number }[]>([]);

  useEffect(() => {
    if (!data) return;
    const net = data.network;
    if (!net) return;

    const rx = net.lan?.rx_bytes_per_sec ?? 0;
    const tx = net.lan?.tx_bytes_per_sec ?? 0;

    valuesRef.current.push({ rx, tx });
    if (valuesRef.current.length > 60) valuesRef.current.shift();

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const container = canvas.parentElement;
    if (!container) return;
    canvas.width = container.clientWidth;
    canvas.height = 240;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    if (valuesRef.current.length < 2) return;

    const maxVal = Math.max(
      ...valuesRef.current.map((v) => Math.max(v.rx, v.tx)),
      1
    );
    const n = valuesRef.current.length;
    const w = canvas.width / (n - 1);
    const h = canvas.height;

    ctx.strokeStyle = "rgba(148, 163, 184, 0.1)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = (h / 4) * i;
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }

    ctx.strokeStyle = "#22c55e";
    ctx.lineWidth = 2;
    ctx.beginPath();
    valuesRef.current.forEach((v, i) => {
      const x = i * w;
      const y = h - (v.tx / maxVal) * (h - 8) - 4;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    ctx.strokeStyle = "#06b7dead";
    ctx.lineWidth = 2;
    ctx.beginPath();
    valuesRef.current.forEach((v, i) => {
      const x = i * w;
      const y = h - (v.rx / maxVal) * (h - 8) - 4;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }, [data]);

  return (
    <div className="chart-container" style={{ height: "240px" }}>
      <canvas ref={canvasRef} style={{ imageRendering: "pixelated" }} />
    </div>
  );
};

// --- SystemChart ---

const SystemChart: React.FC<{ data: WebSocketData | null }> = ({ data }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const valuesRef = useRef<{ cpu: number; gpu: number; ram: number; swap: number; vram: number; cpuTemp: number; gpuTemp: number }[]>([]);

  useEffect(() => {
    if (!data) return;

    const cpu = metricValue(data.cpu?.percent) ?? 0;
    const gpu = metricValue(data.gpu?.utilization) ?? 0;
    const ram = metricValue(data.memory?.ram?.percent) ?? 0;
    const swap = metricValue(data.memory?.swap?.percent) ?? 0;
    const vram = metricValue(data.gpu?.memory?.percent) ?? 0;
    const cpuTemp = data.temperature?.cpu?.package_c ?? 0;
    const gpuTemp = metricValue(data.gpu?.temperature) ?? 0;

    valuesRef.current.push({ cpu, gpu, ram, swap, vram, cpuTemp, gpuTemp });
    if (valuesRef.current.length > 60) valuesRef.current.shift();

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const container = canvas.parentElement;
    if (!container) return;
    canvas.width = container.clientWidth;
    canvas.height = 320;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    if (valuesRef.current.length < 2) return;

    const n = valuesRef.current.length;
    const w = canvas.width / (n - 1);
    const h = canvas.height;

    ctx.strokeStyle = "rgba(148, 163, 184, 0.08)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = (h / 4) * i;
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }

    const drawLine = (values: number[], color: string, maxVal: number = 100) => {
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      values.forEach((v, i) => {
        const x = i * w;
        const y = h - (v / maxVal) * (h - 8) - 4;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    };

    drawLine(valuesRef.current.map(v => v.cpu), "#06b7de");
    drawLine(valuesRef.current.map(v => v.gpu), "#a855f7");
    drawLine(valuesRef.current.map(v => v.ram), "#22c55e");
    drawLine(valuesRef.current.map(v => v.swap), "#f59e0b");
    drawLine(valuesRef.current.map(v => v.vram), "#ec4899");
    drawLine(valuesRef.current.map(v => v.cpuTemp), "#ef4444", 100);
    drawLine(valuesRef.current.map(v => v.gpuTemp), "#8b5cf6", 100);
  }, [data]);

  return (
    <div>
      <div className="chart-container" style={{ height: "320px" }}>
        <canvas ref={canvasRef} style={{ imageRendering: "pixelated" }} />
      </div>
      <div className="chart-legend">
        <span className="chart-legend-item"><span className="chart-legend-color" style={{ background: "#06b7de" }}></span>CPU</span>
        <span className="chart-legend-item"><span className="chart-legend-color" style={{ background: "#a855f7" }}></span>GPU</span>
        <span className="chart-legend-item"><span className="chart-legend-color" style={{ background: "#22c55e" }}></span>RAM</span>
        <span className="chart-legend-item"><span className="chart-legend-color" style={{ background: "#f59e0b" }}></span>SWAP</span>
        <span className="chart-legend-item"><span className="chart-legend-color" style={{ background: "#ec4899" }}></span>VRAM</span>
        <span className="chart-legend-item"><span className="chart-legend-color" style={{ background: "#ef4444" }}></span>CPU Temp</span>
        <span className="chart-legend-item"><span className="chart-legend-color" style={{ background: "#8b5cf6" }}></span>GPU Temp</span>
      </div>
    </div>
  );
};

// --- FanControlCard ---

const FanControlCard: React.FC<{ data: WebSocketData | null }> = ({ data }) => {
  const fan = data?.fan
  const fanOn = fan?.fan?.on ?? false
  const cpuTemp = fan?.cpu_temp ?? null
  const controllerActive = fan?.controller?.active ?? false
  const tuyaState = fan?.tuya?.state ?? "unknown"
  const automationMode = fan?.automation?.mode ?? "AUTO"

  return (
    <div className="panel">
      <div className="panel-header">
        <h2 className="panel-title">Cooling & Fan Control</h2>
      </div>
      <div className="panel-body">
        <div className="fan-control-grid">
          <div className="fan-control-row">
            <span className="fan-control-label">Physical Fan</span>
            <span className={`fan-control-value ${fanOn ? "ok" : ""}`}>
              {fanOn ? "ON" : "OFF"}
            </span>
          </div>
          <div className="fan-control-row">
            <span className="fan-control-label">Controller</span>
            <span className={`fan-control-value ${controllerActive ? "ok" : "critical"}`}>
              {controllerActive ? "RUNNING" : "DOWN"}
            </span>
          </div>
          <div className="fan-control-row">
            <span className="fan-control-label">Automation</span>
            <span className="fan-control-value" style={{ color: "var(--cyan)" }}>
              {automationMode}
            </span>
          </div>
          <div className="fan-control-row">
            <span className="fan-control-label">CPU Temperature</span>
            <span className={`fan-control-value ${
              cpuTemp !== null && cpuTemp >= 70 ? "critical" :
              cpuTemp !== null && cpuTemp > 50 ? "warning" : "ok"
            }`}>
              {cpuTemp !== null ? `${cpuTemp.toFixed(0)}°C` : "N/A"}
            </span>
          </div>
          <div className="fan-control-row">
            <span className="fan-control-label">Tuya</span>
            <span className={`fan-control-value ${
              tuyaState === "connected" ? "ok" :
              tuyaState === "degraded" ? "warning" : "critical"
            }`}>
              {tuyaState.toUpperCase()}
            </span>
          </div>
          {fan?.thresholds && (
            <>
              <div className="fan-control-row">
                <span className="fan-control-label">Turn ON</span>
                <span className="fan-control-value">{fan.thresholds.on_temp_c}°C</span>
              </div>
              <div className="fan-control-row">
                <span className="fan-control-label">Turn OFF</span>
                <span className="fan-control-value">{fan.thresholds.off_temp_c}°C</span>
              </div>
              {fan.thresholds.min_on_seconds && (
                <div className="fan-control-row">
                  <span className="fan-control-label">Minimum ON</span>
                  <span className="fan-control-value">{fan.thresholds.min_on_seconds}s</span>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

// --- ServicesCard ---

const ServicesCard: React.FC<{ data: WebSocketData | null }> = ({ data }) => {
  const services = (data?.services as any) ?? {};
  const svcList = services.services || [];
  const counts = services.counts || {};
  const [showAll, setShowAll] = useState(false);

  const priorityServices = svcList.filter((s: any) => s.important !== false).slice(0, 9);
  const otherServices = svcList.filter((s: any) => s.important === false);
  const containers = data?.containers?.containers || [];

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="services-header">
          <h3 className="panel-title">Services & Containers</h3>
          <span className="services-count">{counts.running ?? 0}/{counts.total ?? 0}</span>
        </div>
      </div>
      <div className="panel-body">
        {priorityServices.map((svc: any, i: number) => {
          const isActive = svc.active || svc.active_state === "active" || svc.status?.includes("active");
          const isFailed = svc.failed || svc.sub_state === "failed" || svc.status?.includes("failed");
          return (
            <div key={i} className="service-row">
              <span className="service-name">{svc.display_name || svc.name || svc.unit || "—"}</span>
              <span className={`status-pill ${isActive ? "status-pill-running" : isFailed ? "status-pill-failed" : "status-pill-down"}`}>
                {isActive ? "RUNNING" : isFailed ? "FAILED" : "DOWN"}
              </span>
            </div>
          );
        })}

        {showAll && otherServices.map((svc: any, i: number) => {
          const isActive = svc.active || svc.active_state === "active" || svc.status?.includes("active");
          const isFailed = svc.failed || svc.sub_state === "failed" || svc.status?.includes("failed");
          return (
            <div key={`other-${i}`} className="service-row">
              <span className="service-name">{svc.display_name || svc.name || svc.unit || "—"}</span>
              <span className={`status-pill ${isActive ? "status-pill-running" : isFailed ? "status-pill-failed" : "status-pill-down"}`}>
                {isActive ? "RUNNING" : isFailed ? "FAILED" : "DOWN"}
              </span>
            </div>
          );
        })}

        {otherServices.length > 0 && (
          <div className="services-toggle" onClick={() => setShowAll(!showAll)}>
            {showAll ? "Show fewer" : `Show all ${svcList.length} services`}
          </div>
        )}

        {containers.length > 0 && (
          <div className="containers-section">
            <div className="containers-header">Containers ({containers.length})</div>
            {containers.slice(0, 5).map((c: any, i: number) => (
              <div key={i} className="container-row">
                <span className="container-name">{c.name || "—"}</span>
                <span className="container-status">{c.state || "—"}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// --- ExternalStorageEventLog ---

const AcasisEventLog: React.FC<{
  events: StorageEvent[];
  loading: boolean;
  onEventsRequest: () => void;
}> = ({ events, loading, onEventsRequest }) => {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const toggleExpand = (id: number) => {
    const newSet = new Set(expanded);
    if (newSet.has(id)) newSet.delete(id);
    else newSet.add(id);
    setExpanded(newSet);
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="events-header">
          <h2 className="panel-title">External Storage Event Timeline</h2>
          <button className="events-refresh" onClick={onEventsRequest}>
            Refresh
          </button>
        </div>
      </div>
      <div className="panel-body">
        {loading ? (
          <div className="events-empty">Loading…</div>
        ) : events.length === 0 ? (
          <div className="events-empty">No storage incidents in the selected period.</div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>Severity</th>
                  <th>Device</th>
                  <th>Summary</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <>
                    <tr
                      key={event.id}
                      onClick={() => toggleExpand(event.id)}
                      style={{ cursor: "pointer" }}
                    >
                      <td style={{ color: "var(--text-muted)" }}>{utcToLocale(event.timestamp_utc)}</td>
                      <td>
                        <span style={{
                          color: event.severity === "critical" ? "var(--red)" :
                                 event.severity === "warning" ? "var(--amber)" : "var(--cyan)"
                        }}>
                          {event.event_type}
                        </span>
                      </td>
                      <td style={{ color: "var(--text-muted)" }}>{event.severity}</td>
                      <td>{event.device_path || "—"}</td>
                      <td className="truncate" style={{ maxWidth: "200px" }}>{event.reason || "—"}</td>
                    </tr>
                    {expanded.has(event.id) && (
                      <tr>
                        <td colSpan={5} style={{ padding: "12px", background: "rgba(30,41,59,0.3)" }}>
                          <div style={{ fontSize: "12px", display: "grid", gap: "4px" }}>
                            <div><strong style={{ color: "var(--text-muted)" }}>UUID:</strong> <span style={{ fontFamily: "monospace", color: "var(--cyan)" }}>{event.filesystem_uuid}</span></div>
                            {event.diagnosis && <div><strong style={{ color: "var(--text-muted)" }}>Diagnosis:</strong> {event.diagnosis}</div>}
                            {event.confidence && <div><strong style={{ color: "var(--text-muted)" }}>Confidence:</strong> {event.confidence}</div>}
                            {(event.details_json as any)?.old_state && (
                              <div><strong style={{ color: "var(--text-muted)" }}>Transition:</strong> {(event.details_json as any).old_state} → {(event.details_json as any).new_state}</div>
                            )}
                            {event.mountpoint && <div><strong style={{ color: "var(--text-muted)" }}>Mountpoint:</strong> {event.mountpoint}</div>}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

// --- Authentication ---

interface AuthState {
  checked: boolean;
  enabled: boolean;
  configured: boolean;
  authenticated: boolean;
  username: string | null;
}

const LoginScreen: React.FC<{ configured: boolean; onAuthenticated: (username: string) => void }> = ({ configured, onAuthenticated }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!configured || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        setError(body.detail || "Login failed");
        return;
      }
      onAuthenticated(body.username || username);
    } catch {
      setError("Unable to reach the authentication service");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand">SCC</div>
        <h1>Server Command Center</h1>
        <p className="login-subtitle">Sign in to access live server telemetry.</p>
        {!configured ? (
          <div className="login-error">Authentication is not configured on this server.</div>
        ) : (
          <form onSubmit={submit} className="login-form">
            <label>
              Username
              <input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
            </label>
            <label>
              Password
              <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </label>
            {error && <div className="login-error">{error}</div>}
            <button type="submit" disabled={submitting}>{submitting ? "Signing in…" : "Sign in"}</button>
          </form>
        )}
        <div className="login-footnote">Protected dashboard · Session cookie is HTTP-only</div>
      </div>
    </div>
  );
};

// --- Storage Overview ---

const StorageOverview: React.FC<{ disks: StorageDisk[] }> = ({ disks }) => (
  <div className="panel storage-overview-panel">
    <div className="panel-header storage-overview-header">
      <h2 className="panel-title">Storage Overview</h2>
      <span className="storage-overview-count">{disks.length} mounted filesystem{disks.length === 1 ? "" : "s"}</span>
    </div>
    <div className="panel-body">
      <div className="storage-overview-grid">
        {disks.map((disk) => {
          const health = disk.health || (disk.percent >= 95 ? "critical" : disk.percent >= 85 ? "warning" : "healthy");
          const uuid = disk.uuid ? `${disk.uuid.slice(0, 4)}…${disk.uuid.slice(-4)}` : "—";
          return (
            <div className={`storage-device-card storage-device-${health}`} key={`${disk.device}-${disk.mount}`}>
              <div className="storage-device-head">
                <div>
                  <div className="storage-device-kind">{disk.kind === "external" ? "EXTERNAL" : "INTERNAL"}</div>
                  <div className="storage-device-name">{disk.display_name || disk.model || disk.mount}</div>
                </div>
                <span className={`storage-device-health ${health}`}>{health.toUpperCase()}</span>
              </div>
              <div className="storage-device-usage">{formatBytes(disk.used_bytes)} / {formatBytes(disk.total_bytes)}</div>
              <div className="storage-device-percent">{disk.percent.toFixed(1)}% used · {formatBytes(disk.free_bytes)} free</div>
              <div className="progress-bar storage-device-progress">
                <div className={`progress-fill ${health === "critical" ? "critical" : health === "warning" ? "warning" : "ok"}`} style={{ width: `${Math.min(disk.percent, 100)}%` }} />
              </div>
              <div className="storage-device-meta">
                <span>{disk.mount}</span>
                <span>{disk.fstype?.toUpperCase() || "—"} · {disk.read_only ? "RO" : "RW"}</span>
                <span>{disk.model || disk.parent_device || disk.device || "—"}</span>
                <span>{disk.transport?.toUpperCase() || (disk.kind === "internal" ? "INTERNAL" : "—")}</span>
                <span>UUID {uuid}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  </div>
);

// --- HealthBanner ---

const HealthBanner: React.FC<{ data: WebSocketData | null }> = ({ data }) => {
  if (!data?.health) return null;

  const health = data.health;
  const status = health.status || "unknown";
  const reasons = health.reasons || [];

  return (
    <div className={`health-banner health-banner-${status}`}>
      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        <span className="health-status">{status.toUpperCase()}</span>
        {reasons.length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
            {reasons.map((reason, i) => (
              <span key={i} className="health-chip">
                {reason}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// --- ErrorBoundary ---

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error, errorInfo: null };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    this.setState({ errorInfo });
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-900 flex items-center justify-center p-6">
          <div className="panel" style={{ maxWidth: "600px", width: "100%", padding: "32px" }}>
            <h2 className="text-2xl font-bold text-red-400 mb-4">
              ⚠️ Dashboard Error
            </h2>
            <p className="text-slate-300 mb-4">
              An unexpected error occurred while rendering the dashboard.
              The WebSocket connection and backend services are unaffected.
            </p>
            {this.state.error && (
              <div className="bg-slate-800/50 rounded-lg p-4 mb-4">
                <div className="text-xs text-slate-500 mb-1">Error Message</div>
                <div className="text-sm text-red-300 font-mono break-words">
                  {this.state.error.message}
                </div>
              </div>
            )}
            {this.state.errorInfo && (
              <div className="bg-slate-800/50 rounded-lg p-4 mb-4">
                <div className="text-xs text-slate-500 mb-1">Stack Trace</div>
                <pre className="text-xs text-slate-400 font-mono overflow-x-auto max-h-64 overflow-y-auto whitespace-pre-wrap">
                  {this.state.errorInfo.componentStack}
                </pre>
              </div>
            )}
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-cyan-500/20 text-cyan-400 rounded-lg hover:bg-cyan-500/30 transition-colors"
            >
              Reload Dashboard
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// --- Main App ---

function App() {
  const isDemo = new URLSearchParams(window.location.search).get("demo") === "1";
  const [auth, setAuth] = useState<AuthState>({ checked: isDemo, enabled: true, configured: false, authenticated: isDemo, username: isDemo ? "demo" : null });
  const [wsData, setWsData] = useState<WebSocketData | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [wsError, setWsError] = useState<string | null>(null);
  const [events, setEvents] = useState<StorageEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [showEvents, setShowEvents] = useState(false);
  const [currentTime, setCurrentTime] = useState(new Date());

  const wsProtocol =
    window.location.protocol === "https:" ? "wss:" : "ws:";
  const { data: wsResult, connected, error } = useWebSocket(
    !isDemo && auth.authenticated ? `${wsProtocol}//${window.location.host}/ws/metrics` : ""
  );

  // Demo mode: fetch synthetic snapshot from /api/demo, then poll a few
  // times so the rolling charts accumulate enough samples to render.
  useEffect(() => {
    if (!isDemo) return;
    let cancelled = false;
    async function loadDemo() {
      try {
        const r = await fetch("/api/demo");
        const data = await r.json();
        if (!cancelled) {
          setWsData(data);
          setWsConnected(true);
        }
      } catch {
        if (!cancelled) setWsError("Demo data unavailable");
      }
    }
    loadDemo();
    // Poll every 800ms for ~5s to give charts enough history points.
    const interval = setInterval(loadDemo, 800);
    const timeout = setTimeout(() => clearInterval(interval), 5000);
    return () => { cancelled = true; clearInterval(interval); clearTimeout(timeout); };
  }, [isDemo]);

  useEffect(() => {
    if (isDemo) return;
    let cancelled = false;
    fetch("/api/auth/me", { cache: "no-store" })
      .then((response) => response.json())
      .then((body) => {
        if (cancelled) return;
        setAuth({
          checked: true,
          enabled: body.enabled !== false,
          configured: body.configured !== false,
          authenticated: body.authenticated === true || body.enabled === false,
          username: body.username || null,
        });
      })
      .catch(() => {
        if (!cancelled) setAuth((prev) => ({ ...prev, checked: true, authenticated: false }));
      });
    return () => { cancelled = true; };
  }, [isDemo]);

  async function logout() {
    try { await fetch("/api/auth/logout", { method: "POST" }); } catch { /* ignore */ }
    setAuth((prev) => ({ ...prev, authenticated: false, username: null }));
    setWsData(null);
  }

  // Fetch events via REST
  async function fetchEvents() {
    if (!auth.authenticated) return;
    setEventsLoading(true);
    try {
      const r = await fetch(`/api/storage/events?limit=50`);
      const data = await r.json();
      setEvents(data.events || []);
    } catch {
      // silent
    } finally {
      setEventsLoading(false);
    }
  }

  useEffect(() => {
    setWsData(wsResult);
    setWsConnected(connected);
    setWsError(error);
  }, [wsResult, connected, error]);

  // Initial events load after authentication
  useEffect(() => {
    if (auth.authenticated && !isDemo) fetchEvents();
  }, [auth.authenticated, isDemo]);

  // Auto-refresh events when the events panel is visible
  useEffect(() => {
    if (showEvents && !isDemo) {
      fetchEvents();
    }
  }, [showEvents, isDemo]);

  // Update time every second
  useEffect(() => {
    const interval = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  // Listen for prefers-reduced-motion
  const prefersReducedRef = useRef(false);
  useLayoutEffect(() => {
    prefersReducedRef.current = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;
  }, []);

  const storageExternal = wsData?.storage_external as
    | (StorageExternal & { available?: boolean })
    | undefined;

  // Health indicator — backend sends health.status, not health.overall
  const overallHealth = wsData?.health

  if (!auth.checked) {
    return <div className="login-page"><div className="login-card"><div className="login-brand">SCC</div><p className="login-subtitle">Checking session…</p></div></div>;
  }

  if (auth.enabled && !auth.authenticated) {
    return <LoginScreen configured={auth.configured} onAuthenticated={(username) => setAuth((prev) => ({ ...prev, authenticated: true, username }))} />;
  }

  return (
    <ErrorBoundary>
    <div className="min-h-screen bg-gradient-to-b from-slate-900 via-slate-950 to-slate-900 text-slate-200">
      <div className="dashboard-shell">
        {/* Header */}
        <header className="dashboard-header">
          <div className="header-left">
            <div className="header-logo">SCC</div>
            <div>
              <h1 className="header-title">{wsData?.meta?.host ? `${wsData.meta.host} Command Center` : "Server Command Center"}</h1>
              <div className="header-subtitle">Real-time server monitoring</div>
            </div>
          </div>
          <div className="header-right">
            <div className="ws-status">
              <div className="ws-dot"></div>
              <span>{wsConnected ? "LIVE" : wsError ? "OFFLINE" : "RECONNECTING"}</span>
            </div>
            {overallHealth && (
              <span className={`health-status ${overallHealth.status}`}>
                {overallHealth.status.toUpperCase()}
              </span>
            )}
            <span className="current-time">
              {currentTime.toLocaleTimeString("id-ID", { timeZone: "Asia/Jakarta" })}
            </span>
            {auth.enabled && (
              <button className="logout-button" onClick={logout} title={`Signed in as ${auth.username || "user"}`}>Logout</button>
            )}
          </div>
        </header>

        {/* Health Banner */}
        <HealthBanner data={wsData} />

        {/* ROW 1: Top Metric Cards */}
        <TopCards data={wsData} />

        {/* ROW 2: Cooling & Fan Control | System Performance Live */}
        <div className="cooling-performance-grid">
          <FanControlCard data={wsData} />
          <div className="panel">
            <div className="panel-header">
              <h2 className="panel-title">System Performance Live</h2>
            </div>
            <div className="panel-body">
              <SystemChart data={wsData} />
              {wsData && (
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: "12px", marginTop: "12px", fontSize: "12px" }}>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Load (1m)</span>
                    <div style={{ color: "var(--text)" }}>{wsData.cpu?.load_average?.["1m"]?.toFixed(2) ?? "—"}</div>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Load (5m)</span>
                    <div style={{ color: "var(--text)" }}>{wsData.cpu?.load_average?.["5m"]?.toFixed(2) ?? "—"}</div>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Uptime</span>
                    <div style={{ color: "var(--text)" }}>{wsData.meta?.uptime_seconds ? `${Math.floor(wsData.meta.uptime_seconds)}s` : "N/A"}</div>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>Processes</span>
                    <div style={{ color: "var(--text)" }}>{wsData.processes?.total_processes ?? "—"}</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ROW 3: Process Tables */}
        <div className="process-grid">
          <ProcessTable
            title="Top CPU Processes"
            processes={wsData?.processes?.top_cpu || []}
            cpuSupported={true}
          />
          <ProcessTable
            title="Top RAM Processes"
            processes={wsData?.processes?.top_ram || []}
            cpuSupported={true}
            ramMode={true}
          />
          <GPUProcessTable processes={wsData?.gpu_processes?.processes || []} />
        </div>

        {/* ROW 4: Services & Containers | Network Activity */}
        <div className="services-network-grid">
          <ServicesCard data={wsData} />
          <div className="panel">
            <div className="panel-header">
              <h2 className="panel-title">Network Activity</h2>
            </div>
            <div className="panel-body">
              <NetworkChart data={wsData} />
              {wsData?.network && (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginTop: "12px", fontSize: "12px" }}>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>LAN</span>
                    <div style={{ color: "var(--text)" }}>{wsData.network.active_interface || "—"}</div>
                    <div style={{ color: "var(--green)", fontSize: "11px" }}>ACTIVE</div>
                  </div>
                  <div>
                    <span style={{ color: "var(--text-muted)" }}>RX / TX</span>
                    <div style={{ color: "var(--cyan)" }}>
                      ↓ {(wsData.network.lan?.rx_bytes_per_sec / 1024).toFixed(1)} KB/s · ↑ {(wsData.network.lan?.tx_bytes_per_sec / 1024).toFixed(1)} KB/s
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* STORAGE: all mounted internal + external filesystems */}
        <StorageOverview disks={wsData?.storage?.disks || []} />

        {/* ROW 5: tracked external storage | event timeline */}
        <div className="storage-events-grid">
          <AcasisStorageCard
            data={storageExternal ?? null}
            onEventsClick={() => setShowEvents(true)}
          />
          {showEvents ? (
            <AcasisEventLog
              events={events}
              loading={eventsLoading}
              onEventsRequest={fetchEvents}
            />
          ) : (
            <div className="panel">
              <div className="panel-header">
                <h2 className="panel-title">External Storage Event Timeline</h2>
              </div>
              <div className="panel-body">
                <div className="events-empty">
                  <p className="text-slate-500 text-sm">No storage incidents in the selected period.</p>
                  <button
                    onClick={() => setShowEvents(true)}
                    className="mt-2 text-cyan-400 hover:text-cyan-300 text-sm"
                    style={{ background: "none", border: "none", cursor: "pointer" }}
                  >
                    Load Events →
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Reduced motion indicator */}
      {prefersReducedRef.current && (
        <div className="fixed bottom-4 right-4 text-xs text-slate-500">
          Reduced motion enabled
        </div>
      )}
    </div>
    </ErrorBoundary>
  );
}

export default App;

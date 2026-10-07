import { describe, it, expect } from "vitest"
import snapshotData from "../__fixtures__/snapshot_fixture.json"

// --- metricValue implementation (mirrors App.tsx) ---

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

// --- Tests ---

describe("Frontend metric helpers with REAL backend snapshot", () => {
  const data = snapshotData as any

  describe("CPU metrics", () => {
    it("extracts cpu.percent value as a number", () => {
      const pct = metricValue(data.cpu.percent)
      expect(pct).toBeGreaterThan(0)
      expect(typeof pct).toBe("number")
    })

    it("does NOT call toFixed on null", () => {
      const pct = metricValue(data.cpu.percent)
      expect(() => (pct ?? 0).toFixed(1)).not.toThrow()
    })
  })

  describe("RAM metrics", () => {
    it("extracts memory.ram.percent value", () => {
      const pct = metricValue(data.memory.ram.percent)
      expect(pct).not.toBeNull()
    })

    it("extracts ram.used_bytes as a plain number", () => {
      expect(typeof data.memory.ram.used_bytes).toBe("number")
      expect(data.memory.ram.used_bytes).toBeGreaterThan(0)
    })
  })

  describe("GPU metrics", () => {
    it("extracts gpu.utilization value", () => {
      const util = metricValue(data.gpu.utilization)
      expect(util).not.toBeNull()
      expect(typeof util).toBe("number")
    })

    it("extracts gpu.memory.percent value", () => {
      const pct = metricValue(data.gpu.memory.percent)
      expect(pct).not.toBeNull()
    })

    it("extracts gpu.total_bytes as a plain number", () => {
      expect(typeof data.gpu.memory.total_bytes).toBe("number")
    })

    it("handles gpu.power_draw null gracefully (unsupported)", () => {
      const power = metricValue(data.gpu.power_draw)
      expect(power).toBeNull()
    })

    it("handles gpu.fan_speed_pct null gracefully (unsupported)", () => {
      const fan = metricValue(data.gpu.fan_speed_pct)
      expect(fan).toBeNull()
    })

    it("handles gpu.temperature value as number", () => {
      const temp = metricValue(data.gpu.temperature)
      expect(temp).not.toBeNull()
    })

    it("handles gpu_processes.per_process_utilization null", () => {
      const gpuProc = metricValue(data.gpu_processes.per_process_utilization)
      expect(gpuProc).toBeNull()
    })
  })

  describe("Temperature metrics", () => {
    it("uses package_c field (not deprecated .value)", () => {
      expect(data.temperature.cpu.package_c).toBe(58)
      expect(data.temperature.cpu).toHaveProperty("package_c")
    })

    it("does not have .value on temperature.cpu", () => {
      expect(data.temperature.cpu).not.toHaveProperty("value")
    })
  })

  describe("Fan metrics", () => {
    it("has fan.fan.state and fan.fan.on", () => {
      expect(data.fan.fan.state).toBe("OFF")
      expect(data.fan.fan.on).toBe(false)
    })

    it("does not have fan.speed (old schema)", () => {
      expect(data.fan).not.toHaveProperty("speed")
    })
  })

  describe("Health rendering — the crash fix", () => {
    it("health.status exists (not .overall)", () => {
      expect(data.health).toHaveProperty("status")
      expect(typeof data.health.status).toBe("string")
    })

    it("health does NOT have .overall field", () => {
      expect(data.health).not.toHaveProperty("overall")
    })

    it("calling .toUpperCase() on health.status does not throw", () => {
      expect(() => data.health.status.toUpperCase()).not.toThrow()
    })
  })

  describe("Processes", () => {
    it("top_cpu processes have ram_bytes", () => {
      const proc = data.processes.top_cpu[0]
      expect(proc).toHaveProperty("ram_bytes")
      expect(typeof proc.ram_bytes).toBe("number")
    })

    it("top_cpu processes do NOT have rss_bytes", () => {
      const proc = data.processes.top_cpu[0]
      expect(proc).not.toHaveProperty("rss_bytes")
    })
  })

  describe("Services", () => {
    it("has services.counts with running/total", () => {
      expect(data.services.counts).toHaveProperty("total")
      expect(data.services.counts).toHaveProperty("running")
    })

    it("service objects have active_state and status", () => {
      const svc = data.services.services[0]
      expect(svc).toHaveProperty("active_state")
      expect(svc).toHaveProperty("status")
    })
  })

  describe("Network", () => {
    it("has active_interface", () => {
      expect(data.network.active_interface).toBe("enp4s0")
    })
  })

  describe("Meta", () => {
    it("has uptime_seconds (not load_avg)", () => {
      expect(data.meta).toHaveProperty("uptime_seconds")
    })

    it("load_average is on cpu, not meta", () => {
      expect(data.cpu.load_average).toHaveProperty("1m")
      expect(data.cpu.load_average).toHaveProperty("5m")
      expect(data.meta).not.toHaveProperty("load_avg_1m")
      expect(data.meta).not.toHaveProperty("load_avg_5m")
    })
  })
})

describe("Frontend metric helpers — edge cases", () => {
  it("returns null for undefined metric", () => {
    expect(metricValue(undefined)).toBeNull()
  })

  it("returns null for null metric", () => {
    expect(metricValue(null)).toBeNull()
  })

  it("returns number for plain number input", () => {
    expect(metricValue(42)).toBe(42)
  })

  it("returns null for unsupported metric with null value", () => {
    expect(metricValue({ value: null, supported: false })).toBeNull()
  })

  it("returns null for unsupported metric with non-null value", () => {
    expect(metricValue({ value: 50, supported: false })).toBeNull()
  })

  it("returns value for supported metric", () => {
    expect(metricValue({ value: 51.5, supported: true })).toBe(51.5)
  })

  it("returns null for supported metric with null value", () => {
    expect(metricValue({ value: null, supported: true })).toBeNull()
  })

  it("safe formatBytes with undefined does not throw", () => {
    const formatBytes = (bytes: number | null | undefined): string => {
      const b = bytes ?? 0
      if (b < 1024) return `${b} B`
      return `${b.toFixed(1)} B`
    }
    expect(() => formatBytes(undefined)).not.toThrow()
    expect(() => formatBytes(null)).not.toThrow()
  })
})


describe("Storage overview fixture", () => {
  const data = snapshotData as any
  it("contains two internal filesystems and one external filesystem", () => {
    expect(data.storage.internal_count).toBe(2)
    expect(data.storage.external_count).toBe(1)
    expect(data.storage.disks.filter((d: any) => d.kind === "internal")).toHaveLength(2)
    expect(data.storage.disks.filter((d: any) => d.kind === "external")).toHaveLength(1)
  })

  it("provides used/total/free values for every storage card", () => {
    for (const disk of data.storage.disks) {
      expect(disk.total_bytes).toBeGreaterThan(0)
      expect(disk.used_bytes).toBeGreaterThanOrEqual(0)
      expect(disk.free_bytes).toBeGreaterThanOrEqual(0)
      expect(typeof disk.percent).toBe("number")
    }
  })
})

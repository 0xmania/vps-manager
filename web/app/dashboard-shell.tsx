'use client';

import { type SyntheticEvent, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Bell,
  Box,
  ChevronRight,
  CircleGauge,
  CloudCog,
  Command,
  Fingerprint,
  Gauge,
  History,
  KeyRound,
  LayoutDashboard,
  LifeBuoy,
  LockKeyhole,
  Network,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Server,
  Settings2,
  ShieldCheck,
  TerminalSquare,
} from 'lucide-react';

import { OperationsWorkspace } from '@/app/operations-workspace';
import { pollControlPlaneJob } from '@/lib/job-poller';
import { Avatar, AvatarBadge, AvatarFallback } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import {
  NativeSelect,
  NativeSelectOption,
} from '@/components/ui/native-select';
import {
  Progress,
  ProgressLabel,
  ProgressValue,
} from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

type HostStatus = 'online' | 'warning' | 'offline';

type Host = {
  id: string;
  version: number;
  name: string;
  address: string;
  region: string;
  os: string;
  status: HostStatus;
  latency: string;
  cpu: number;
  memory: number;
  disk: number;
  load: string;
  uptime: string;
  findings: number;
  fingerprint: 'verified' | 'pending';
  snapshotAvailable: boolean;
};

type ControlPlaneHost = {
  id: string;
  version: number;
  name: string;
  address: string;
  port: number;
  username: string;
  labels?: Record<string, string>;
  hostKey?: { fingerprintSha256: string };
};

type HostKeyProbe = {
  hostId: string;
  hostVersion: number;
  algorithm: string;
  fingerprintSha256: string;
  publicKey: string;
  resolvedAddress: string;
  observedAt: string;
  trusted: false;
};

type DataMode = 'loading' | 'live' | 'demo';

type ControlPlaneAuditEvent = {
  id: string;
  timestamp: string;
  action: string;
  targetId?: string;
  outcome: string;
};

type AuditEventView = {
  title: string;
  detail: string;
  time: string;
  tone: 'ok' | 'warn' | 'alert';
};

type RuntimeSnapshot = {
  kernel?: string;
  uptimeSeconds?: number;
  cpuUsagePercent?: number;
  load?: [number, number, number];
  memoryTotalBytes?: number;
  memoryAvailableBytes?: number;
  filesystems?: Array<{
    mount: string;
    totalBytes: number;
    usedBytes: number;
  }>;
  fieldErrors?: Record<string, string>;
};

type ControlPlaneJob = {
  id: string;
  state:
    | 'queued'
    | 'running'
    | 'succeeded'
    | 'failed'
    | 'timed_out'
    | 'cancelled';
  snapshot?: RuntimeSnapshot;
  error?: { message?: string };
};

const initialHosts: Host[] = [
  {
    id: 'edge-hkg-01',
    version: 1,
    name: 'edge-hkg-01',
    address: '103.84.7.21',
    region: '香港',
    os: 'Ubuntu 24.04',
    status: 'online',
    latency: '38 ms',
    cpu: 24,
    memory: 61,
    disk: 43,
    load: '0.42',
    uptime: '19 天 6 小时',
    findings: 1,
    fingerprint: 'verified',
    snapshotAvailable: true,
  },
  {
    id: 'api-sgp-02',
    version: 1,
    name: 'api-sgp-02',
    address: '45.77.36.118',
    region: '新加坡',
    os: 'Debian 12',
    status: 'warning',
    latency: '72 ms',
    cpu: 79,
    memory: 74,
    disk: 66,
    load: '2.18',
    uptime: '8 天 11 小时',
    findings: 2,
    fingerprint: 'verified',
    snapshotAvailable: true,
  },
  {
    id: 'worker-fra-01',
    version: 1,
    name: 'worker-fra-01',
    address: '91.107.221.63',
    region: '法兰克福',
    os: 'Ubuntu 24.04',
    status: 'online',
    latency: '186 ms',
    cpu: 11,
    memory: 38,
    disk: 28,
    load: '0.17',
    uptime: '31 天 2 小时',
    findings: 0,
    fingerprint: 'verified',
    snapshotAvailable: true,
  },
  {
    id: 'backup-lax-01',
    version: 1,
    name: 'backup-lax-01',
    address: '149.28.91.204',
    region: '洛杉矶',
    os: '待识别',
    status: 'offline',
    latency: '—',
    cpu: 0,
    memory: 0,
    disk: 0,
    load: '—',
    uptime: '—',
    findings: 0,
    fingerprint: 'pending',
    snapshotAvailable: false,
  },
];

const emptyHost: Host = {
  id: 'empty',
  version: 0,
  name: '尚未添加 VPS',
  address: '—',
  region: '—',
  os: '—',
  status: 'offline',
  latency: '—',
  cpu: 0,
  memory: 0,
  disk: 0,
  load: '—',
  uptime: '—',
  findings: 0,
  fingerprint: 'pending',
  snapshotAvailable: false,
};

function mapControlPlaneHost(host: ControlPlaneHost): Host {
  return {
    id: host.id,
    version: host.version,
    name: host.name,
    address: `${host.address}:${host.port}`,
    region: host.labels?.region ?? '未分组',
    os: '等待运行快照',
    status: host.hostKey ? 'warning' : 'offline',
    latency: '—',
    cpu: 0,
    memory: 0,
    disk: 0,
    load: '—',
    uptime: '—',
    findings: 0,
    fingerprint: host.hostKey ? 'verified' : 'pending',
    snapshotAvailable: false,
  };
}

const navItems = [
  { label: '运行总览', icon: LayoutDashboard, active: true },
  { label: 'VPS 资产', icon: Server },
  { label: '任务中心', icon: CircleGauge, count: 2 },
  { label: 'Web SSH', icon: TerminalSquare },
  { label: '异常扫描', icon: Radar, count: 3 },
  { label: 'Workers 部署', icon: CloudCog },
];

const systemItems = [
  { label: '凭据中心', icon: KeyRound },
  { label: '审计记录', icon: History },
  { label: '权限与认证', icon: LockKeyhole },
  { label: '平台设置', icon: Settings2 },
];

const demoAuditEvents: AuditEventView[] = [
  {
    title: '运行快照已更新',
    detail: 'edge-hkg-01 · 14 项采集器成功',
    time: '刚刚',
    tone: 'ok',
  },
  {
    title: '发现高资源进程',
    detail: 'api-sgp-02 · node 占用 CPU 68%',
    time: '8 分钟前',
    tone: 'warn',
  },
  {
    title: '主机指纹待确认',
    detail: 'backup-lax-01 · SHA256 指纹未固定',
    time: '26 分钟前',
    tone: 'alert',
  },
];

const auditActionLabels: Record<string, string> = {
  'session.created': '开发会话已建立',
  'host.created': 'VPS 已登记',
  'host.updated': 'VPS 资料已更新',
  'host.deleted': 'VPS 已删除',
  'host_key.pinned': 'SSH 主机指纹已固定',
  'credential.stored': 'SSH 凭据已加密保存',
  'credential.deleted': 'SSH 凭据已删除',
  'job.created': '运行快照任务已提交',
  'job.finished': '运行快照任务已结束',
  'authorization.denied': '权限校验已拒绝请求',
};

function mapAuditEvent(event: ControlPlaneAuditEvent): AuditEventView {
  return {
    title: auditActionLabels[event.action] ?? event.action,
    detail: event.targetId ? `目标 ${event.targetId}` : '控制面事件',
    time: new Date(event.timestamp).toLocaleTimeString('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
    }),
    tone:
      event.outcome === 'denied' || event.outcome === 'failed'
        ? 'alert'
        : event.outcome === 'success'
          ? 'ok'
          : 'warn',
  };
}

function percent(used: number, total: number) {
  if (!Number.isFinite(used) || !Number.isFinite(total) || total <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((used / total) * 100)));
}

function formatUptime(seconds = 0) {
  if (!seconds) return '—';
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  return `${days} 天 ${hours} 小时`;
}

const statusMeta: Record<HostStatus, { label: string; className: string }> = {
  online: {
    label: '在线',
    className: 'border-emerald-400/20 bg-emerald-400/10 text-emerald-300',
  },
  warning: {
    label: '需关注',
    className: 'border-amber-400/20 bg-amber-400/10 text-amber-300',
  },
  offline: {
    label: '待接入',
    className: 'border-slate-400/20 bg-slate-400/10 text-slate-300',
  },
};

function MetricCard({
  label,
  value,
  note,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string;
  note: string;
  icon: typeof Activity;
  accent: string;
}) {
  return (
    <Card className="border-white/5 bg-[linear-gradient(145deg,rgba(22,31,48,.96),rgba(15,23,37,.94))] shadow-[0_18px_48px_rgba(3,8,18,.28)] ring-white/7">
      <CardHeader>
        <CardDescription className="flex items-center gap-2 text-slate-400">
          <span className={`rounded-lg p-1.5 ${accent}`}>
            <Icon className="size-3.5" />
          </span>
          {label}
        </CardDescription>
        <CardTitle className="mt-2 font-mono text-2xl font-semibold tracking-[-0.04em] text-slate-50">
          {value}
        </CardTitle>
      </CardHeader>
      <CardContent className="text-xs text-slate-500">{note}</CardContent>
    </Card>
  );
}

function NavGroup({ title, items }: { title: string; items: typeof navItems }) {
  return (
    <div>
      <p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-600">
        {title}
      </p>
      <nav className="space-y-1" aria-label={title}>
        {items.map(({ label, icon: Icon, active, count }) => (
          <button
            key={label}
            type="button"
            className={`group flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-colors ${
              active
                ? 'bg-cyan-300/10 text-cyan-100'
                : 'text-slate-400 hover:bg-white/5 hover:text-slate-100'
            }`}
          >
            <Icon
              className={`size-4 ${active ? 'text-cyan-300' : 'text-slate-500 group-hover:text-slate-300'}`}
            />
            <span className="flex-1">{label}</span>
            {count ? (
              <span className="rounded-full bg-white/8 px-1.5 font-mono text-[10px] text-slate-300">
                {count}
              </span>
            ) : null}
          </button>
        ))}
      </nav>
    </div>
  );
}

export function DashboardShell({
  user,
  signOutHref,
}: {
  user: { displayName: string; email: string };
  signOutHref: string;
}) {
  const [hostList, setHostList] = useState(initialHosts);
  const [activityEvents, setActivityEvents] = useState(demoAuditEvents);
  const [selectedId, setSelectedId] = useState(initialHosts[0].id);
  const [dataMode, setDataMode] = useState<DataMode>('loading');
  const [query, setQuery] = useState('');
  const [addOpen, setAddOpen] = useState(false);
  const [savingHost, setSavingHost] = useState(false);
  const [formError, setFormError] = useState('');
  const [hostKeyProbe, setHostKeyProbe] = useState<HostKeyProbe | null>(null);
  const [probingHostKey, setProbingHostKey] = useState(false);
  const [pinningHostKey, setPinningHostKey] = useState(false);
  const [confirmedOutOfBand, setConfirmedOutOfBand] = useState(false);
  const [notice, setNotice] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefresh, setLastRefresh] = useState('刚刚');
  const [newHost, setNewHost] = useState({
    name: '',
    address: '',
    region: '香港',
    port: '22',
    username: 'vpsadmin',
  });
  const selected =
    hostList.find((host) => host.id === selectedId) ?? hostList[0] ?? emptyHost;
  const visibleHosts = useMemo(
    () =>
      hostList.filter((host) =>
        `${host.name} ${host.address} ${host.region}`
          .toLowerCase()
          .includes(query.toLowerCase()),
      ),
    [hostList, query],
  );
  const onlineCount = hostList.filter(
    (host) => host.status !== 'offline',
  ).length;
  const verifiedCount = hostList.filter(
    (host) => host.fingerprint === 'verified',
  ).length;
  const identityPercent = hostList.length
    ? Math.round((verifiedCount / hostList.length) * 100)
    : 0;
  const dataModeMeta: Record<DataMode, { label: string; className: string }> = {
    loading: {
      label: 'CONTROL PLANE CONNECTING',
      className: 'border-slate-300/20 bg-slate-300/8 text-slate-300',
    },
    live: {
      label: 'CONTROL PLANE CONNECTED',
      className: 'border-emerald-300/20 bg-emerald-300/8 text-emerald-300',
    },
    demo: {
      label: 'DEMO DATA · API OFFLINE',
      className: 'border-amber-300/20 bg-amber-300/8 text-amber-300',
    },
  };

  useEffect(() => {
    const controller = new AbortController();

    async function loadHosts() {
      try {
        const response = await fetch('/api/control-plane/hosts', {
          cache: 'no-store',
          signal: controller.signal,
        });
        if (!response.ok) throw new Error('control plane unavailable');
        const payload = (await response.json()) as {
          items?: ControlPlaneHost[];
        };
        if (!Array.isArray(payload.items)) throw new Error('invalid host list');
        const hosts = payload.items.map(mapControlPlaneHost);
        setHostList(hosts);
        setSelectedId((current) =>
          hosts.some((host) => host.id === current)
            ? current
            : (hosts[0]?.id ?? ''),
        );
        setDataMode('live');

        const auditResponse = await fetch('/api/control-plane/audit-events', {
          cache: 'no-store',
          signal: controller.signal,
        });
        if (auditResponse.ok) {
          const auditPayload = (await auditResponse.json()) as {
            items?: ControlPlaneAuditEvent[];
          };
          if (Array.isArray(auditPayload.items)) {
            setActivityEvents(auditPayload.items.map(mapAuditEvent));
          }
        }
      } catch (error) {
        if (error instanceof DOMException && error.name === 'AbortError')
          return;
        setDataMode('demo');
      }
    }

    void loadHosts();
    return () => controller.abort();
  }, []);

  async function refreshSnapshots() {
    setRefreshing(true);
    setNotice('');

    if (dataMode !== 'live' || selected.id === emptyHost.id) {
      window.setTimeout(() => {
        setRefreshing(false);
        setLastRefresh('刚刚');
        setNotice('当前为演示数据；连接本地控制面后可创建真实快照任务。');
      }, 850);
      return;
    }

    try {
      const response = await fetch(
        `/api/control-plane/hosts/${encodeURIComponent(selected.id)}/runtime-snapshots`,
        { method: 'POST' },
      );
      const payload = (await response.json()) as
        | ControlPlaneJob
        | { error?: { message?: string } };
      if (!response.ok || !('id' in payload)) {
        throw new Error(
          'error' in payload && payload.error?.message
            ? payload.error.message
            : '无法创建运行快照任务',
        );
      }

      const job = await pollControlPlaneJob<ControlPlaneJob>(payload.id);

      if (job.state !== 'succeeded' || !job.snapshot) {
        throw new Error(job.error?.message ?? `快照任务状态：${job.state}`);
      }

      const snapshot = job.snapshot;
      const rootFilesystem =
        snapshot.filesystems?.find((item) => item.mount === '/') ??
        snapshot.filesystems?.[0];
      const memoryUsed =
        (snapshot.memoryTotalBytes ?? 0) - (snapshot.memoryAvailableBytes ?? 0);
      setHostList((current) =>
        current.map((host) =>
          host.id === selected.id
            ? {
                ...host,
                os: snapshot.kernel ?? host.os,
                status: 'online',
                cpu: Math.round(snapshot.cpuUsagePercent ?? host.cpu),
                memory: percent(memoryUsed, snapshot.memoryTotalBytes ?? 0),
                disk: rootFilesystem
                  ? percent(rootFilesystem.usedBytes, rootFilesystem.totalBytes)
                  : host.disk,
                load: snapshot.load?.[0]?.toFixed(2) ?? '—',
                uptime: formatUptime(snapshot.uptimeSeconds),
                snapshotAvailable: true,
              }
            : host,
        ),
      );
      setLastRefresh('刚刚');
      const partialCount = Object.keys(snapshot.fieldErrors ?? {}).length;
      setNotice(
        partialCount
          ? `运行快照已完成，${partialCount} 个字段采集失败并已保留错误证据。`
          : '运行快照已完成，数据来自已固定身份的目标主机。',
      );
    } catch (error) {
      setNotice(error instanceof Error ? error.message : '运行快照失败');
    } finally {
      setRefreshing(false);
    }
  }

  async function probeHostKey(hostId: string, hostVersion: number) {
    setProbingHostKey(true);
    setNotice('');
    try {
      const response = await fetch(
        `/api/control-plane/hosts/${encodeURIComponent(hostId)}/host-key/probe`,
        { method: 'POST' },
      );
      const payload = (await response.json()) as
        | Omit<HostKeyProbe, 'hostId' | 'hostVersion'>
        | { error?: { message?: string } };
      if (!response.ok || !('fingerprintSha256' in payload)) {
        throw new Error(
          'error' in payload && payload.error?.message
            ? payload.error.message
            : '无法获取 SSH 主机指纹',
        );
      }
      setConfirmedOutOfBand(false);
      setHostKeyProbe({ ...payload, hostId, hostVersion });
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : 'SSH 主机指纹探测失败',
      );
    } finally {
      setProbingHostKey(false);
    }
  }

  async function pinHostKey() {
    if (!hostKeyProbe || !confirmedOutOfBand) return;
    setPinningHostKey(true);
    try {
      const response = await fetch(
        `/api/control-plane/hosts/${encodeURIComponent(hostKeyProbe.hostId)}/host-key`,
        {
          method: 'PUT',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            version: hostKeyProbe.hostVersion,
            publicKey: hostKeyProbe.publicKey,
            expectedFingerprintSha256: hostKeyProbe.fingerprintSha256,
          }),
        },
      );
      const payload = (await response.json()) as
        | ControlPlaneHost
        | { error?: { message?: string } };
      if (!response.ok || !('id' in payload)) {
        throw new Error(
          'error' in payload && payload.error?.message
            ? payload.error.message
            : '控制面拒绝固定该主机指纹',
        );
      }
      const updated = mapControlPlaneHost(payload);
      setHostList((current) =>
        current.map((host) => (host.id === updated.id ? updated : host)),
      );
      setHostKeyProbe(null);
      setConfirmedOutOfBand(false);
      setNotice('SSH 主机指纹已固定；后续握手如发生变化，任务会立即阻断。');
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : '固定 SSH 主机指纹失败',
      );
    } finally {
      setPinningHostKey(false);
    }
  }

  async function addHost(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setSavingHost(true);
    setFormError('');
    try {
      const response = await fetch('/api/control-plane/hosts', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          name: newHost.name.trim(),
          address: newHost.address.trim(),
          port: Number(newHost.port),
          username: newHost.username.trim(),
          labels: { region: newHost.region },
        }),
      });
      const payload = (await response.json()) as
        | ControlPlaneHost
        | { error?: { message?: string } };
      if (!response.ok || !('id' in payload)) {
        throw new Error(
          'error' in payload && payload.error?.message
            ? payload.error.message
            : '控制面拒绝了这台主机',
        );
      }
      const host = mapControlPlaneHost(payload);
      setHostList((current) => [...current, host]);
      setSelectedId(host.id);
      setDataMode('live');
      setNotice('VPS 已写入控制面；请通过独立渠道核对 SSH 主机指纹。');
      setNewHost({
        name: '',
        address: '',
        region: '香港',
        port: '22',
        username: 'vpsadmin',
      });
      setAddOpen(false);
      await probeHostKey(host.id, host.version);
    } catch (error) {
      setFormError(
        error instanceof Error ? error.message : '保存失败，请稍后重试',
      );
    } finally {
      setSavingHost(false);
    }
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="mx-auto grid min-h-screen max-w-[1720px] grid-cols-1 lg:grid-cols-[228px_minmax(0,1fr)]">
        <aside className="hidden border-r border-white/6 bg-[#0b1220]/95 px-4 py-5 lg:flex lg:flex-col">
          <div className="flex items-center gap-3 px-2">
            <div className="grid size-9 place-items-center rounded-xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-300 shadow-[0_0_22px_rgba(61,214,214,.1)]">
              <Network className="size-4.5" />
            </div>
            <div>
              <p className="text-sm font-semibold tracking-tight text-slate-100">
                VPS Manager
              </p>
              <p className="font-mono text-[10px] uppercase tracking-[0.13em] text-slate-600">
                control plane / 01
              </p>
            </div>
          </div>

          <div className="mt-8 space-y-7">
            <NavGroup title="工作台" items={navItems} />
            <NavGroup title="系统" items={systemItems} />
          </div>

          <div className="mt-auto rounded-xl border border-white/7 bg-white/[0.025] p-3">
            <div className="mb-3 flex items-center gap-2 text-xs text-slate-300">
              <ShieldCheck className="size-4 text-emerald-300" />
              本地安全模式
            </div>
            <p className="text-[11px] leading-5 text-slate-500">
              凭据仅在 Connector 任务内临时使用，生产接入尚未开启。
            </p>
          </div>
        </aside>

        <section className="min-w-0">
          <header className="flex h-[72px] items-center gap-4 border-b border-white/6 bg-[#0d1524]/80 px-4 backdrop-blur-xl sm:px-6 xl:px-8">
            <div className="flex items-center gap-2 lg:hidden">
              <div className="grid size-8 place-items-center rounded-lg bg-cyan-300/10 text-cyan-300">
                <Network className="size-4" />
              </div>
              <span className="text-sm font-semibold">VPS Manager</span>
            </div>
            <div className="relative hidden max-w-md flex-1 md:block">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-600" />
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="搜索主机、IP 或区域"
                aria-label="搜索主机、IP 或区域"
                className="h-9 border-white/7 bg-white/[0.035] pl-9 text-slate-200 placeholder:text-slate-600"
              />
            </div>
            <div className="ml-auto flex items-center gap-3">
              <Badge
                variant="outline"
                className={`hidden font-mono text-[10px] sm:inline-flex ${dataModeMeta[dataMode].className}`}
              >
                {dataModeMeta[dataMode].label}
              </Badge>
              <Button
                variant="ghost"
                size="icon"
                aria-label="通知"
                className="text-slate-400 hover:bg-white/5 hover:text-white"
              >
                <Bell className="size-4" />
              </Button>
              <Separator orientation="vertical" className="h-7 bg-white/8" />
              <Avatar size="sm">
                <AvatarFallback className="bg-cyan-300/10 text-cyan-200">
                  {(user.displayName[0] ?? 'A').toUpperCase()}
                </AvatarFallback>
                <AvatarBadge className="bg-emerald-400" />
              </Avatar>
              <div className="hidden min-w-0 sm:block">
                <p className="max-w-36 truncate text-xs font-medium text-slate-200">
                  {user.displayName}
                </p>
                <p className="text-[10px] text-slate-600">管理员</p>
              </div>
              <a
                href={signOutHref}
                className="text-[11px] text-slate-500 transition-colors hover:text-slate-200"
              >
                退出
              </a>
            </div>
          </header>

          <div className="px-4 py-6 sm:px-6 xl:px-8">
            {notice ? (
              <output className="mb-4 flex items-center justify-between rounded-lg border border-cyan-300/12 bg-cyan-300/[0.045] px-3 py-2 text-xs text-cyan-100/70">
                <span>{notice}</span>
                <button
                  type="button"
                  onClick={() => setNotice('')}
                  className="text-cyan-100/45 hover:text-cyan-100"
                >
                  关闭
                </button>
              </output>
            ) : null}
            <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <div className="mb-2 flex items-center gap-2 text-xs text-slate-500">
                  <Activity className="size-3.5 text-cyan-300" />
                  <span>运行总览</span>
                  <ChevronRight className="size-3" />
                  <span>全部主机</span>
                </div>
                <h1 className="text-2xl font-semibold tracking-[-0.035em] text-slate-50 sm:text-[28px]">
                  基础设施运行态势
                </h1>
                <p className="mt-1 text-sm text-slate-500">
                  最近一次采集于{lastRefresh} · {onlineCount} 台在线，
                  {hostList.length - onlineCount} 台等待身份确认
                </p>
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => void refreshSnapshots()}
                  disabled={refreshing || selected.id === emptyHost.id}
                  className="h-9 border-white/8 bg-white/[0.025] text-slate-300 hover:bg-white/6"
                >
                  <RefreshCw
                    className={`size-3.5 ${refreshing ? 'animate-spin' : ''}`}
                  />
                  {refreshing ? '采集中' : '刷新所选快照'}
                </Button>
                <Button
                  onClick={() => setAddOpen(true)}
                  className="h-9 bg-cyan-300 text-slate-950 hover:bg-cyan-200"
                >
                  <Plus className="size-3.5" />
                  添加 VPS
                </Button>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <MetricCard
                label="受管主机"
                value={String(hostList.length).padStart(2, '0')}
                note={`${onlineCount} 在线 · ${hostList.length - onlineCount} 等待接入`}
                icon={Server}
                accent="bg-cyan-300/10 text-cyan-300"
              />
              <MetricCard
                label="活动任务"
                value={dataMode === 'demo' ? '02' : '00'}
                note={
                  dataMode === 'demo'
                    ? '演示：运行快照 · 日志采集'
                    : '当前没有进行中的任务'
                }
                icon={Gauge}
                accent="bg-violet-300/10 text-violet-300"
              />
              <MetricCard
                label="风险发现"
                value={dataMode === 'demo' ? '03' : '00'}
                note={
                  dataMode === 'demo'
                    ? '演示：0 严重 · 2 中等 · 1 提醒'
                    : '异常扫描将在第二周接入'
                }
                icon={Radar}
                accent="bg-amber-300/10 text-amber-300"
              />
              <MetricCard
                label="身份可信"
                value={`${identityPercent}%`}
                note={`${hostList.length - verifiedCount} 台主机指纹待确认`}
                icon={Fingerprint}
                accent="bg-emerald-300/10 text-emerald-300"
              />
            </div>

            <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.65fr)_minmax(330px,.72fr)]">
              <div className="space-y-5">
                <Card className="border-white/5 bg-[#101a2b]/88 ring-white/7">
                  <CardHeader className="border-b border-white/6 pb-4">
                    <CardTitle className="text-sm font-semibold text-slate-100">
                      VPS 资产
                    </CardTitle>
                    <CardDescription className="text-xs text-slate-500">
                      选择主机查看实时快照与安全状态
                    </CardDescription>
                    <CardAction>
                      <Badge
                        variant="outline"
                        className="border-white/8 bg-white/[0.025] font-mono text-[10px] text-slate-400"
                      >
                        {visibleHosts.length} NODES
                      </Badge>
                    </CardAction>
                  </CardHeader>
                  <CardContent className="px-0">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-white/6 hover:bg-transparent">
                          <TableHead className="pl-4 text-[11px] text-slate-500">
                            主机
                          </TableHead>
                          <TableHead className="text-[11px] text-slate-500">
                            状态
                          </TableHead>
                          <TableHead className="hidden text-[11px] text-slate-500 md:table-cell">
                            系统
                          </TableHead>
                          <TableHead className="hidden text-[11px] text-slate-500 lg:table-cell">
                            CPU / 内存
                          </TableHead>
                          <TableHead className="text-right text-[11px] text-slate-500">
                            延迟
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {visibleHosts.map((host) => {
                          const meta = statusMeta[host.status];
                          return (
                            <TableRow
                              key={host.id}
                              data-state={
                                host.id === selectedId ? 'selected' : undefined
                              }
                              onClick={() => setSelectedId(host.id)}
                              className="cursor-pointer border-white/5 hover:bg-white/[0.035] data-[state=selected]:bg-cyan-300/[0.055]"
                            >
                              <TableCell className="pl-4">
                                <div className="flex items-center gap-3">
                                  <span
                                    className={`size-1.5 rounded-full ${host.status === 'online' ? 'bg-emerald-400 shadow-[0_0_9px_rgba(52,211,153,.7)]' : host.status === 'warning' ? 'bg-amber-400 shadow-[0_0_9px_rgba(251,191,36,.6)]' : 'bg-slate-600'}`}
                                  />
                                  <div>
                                    <p className="font-mono text-xs font-medium text-slate-200">
                                      {host.name}
                                    </p>
                                    <p className="mt-0.5 font-mono text-[10px] text-slate-600">
                                      {host.address} · {host.region}
                                    </p>
                                  </div>
                                </div>
                              </TableCell>
                              <TableCell>
                                <Badge
                                  variant="outline"
                                  className={`font-mono text-[10px] ${meta.className}`}
                                >
                                  {meta.label}
                                </Badge>
                              </TableCell>
                              <TableCell className="hidden text-xs text-slate-400 md:table-cell">
                                {host.os}
                              </TableCell>
                              <TableCell className="hidden lg:table-cell">
                                <span className="font-mono text-[11px] text-slate-400">
                                  {host.status === 'offline'
                                    ? '—'
                                    : `${host.cpu}% / ${host.memory}%`}
                                </span>
                              </TableCell>
                              <TableCell className="text-right font-mono text-[11px] text-slate-500">
                                {host.latency}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                <Card className="border-white/5 bg-[#101a2b]/88 ring-white/7">
                  <CardHeader>
                    <CardTitle className="text-sm text-slate-100">
                      最近活动
                    </CardTitle>
                    <CardDescription className="text-xs text-slate-500">
                      控制面与 Connector 产生的可追踪事件
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-1">
                    {activityEvents.length ? (
                      activityEvents.map((event, index) => (
                        <div
                          key={`${event.title}-${event.time}-${index}`}
                          className="flex items-center gap-3 rounded-lg px-1 py-3"
                        >
                          <span
                            className={`size-2 rounded-full ${event.tone === 'ok' ? 'bg-emerald-400' : event.tone === 'warn' ? 'bg-amber-400' : 'bg-cyan-300'}`}
                          />
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-medium text-slate-300">
                              {event.title}
                            </p>
                            <p className="mt-0.5 truncate text-[11px] text-slate-600">
                              {event.detail}
                            </p>
                          </div>
                          <span className="text-[10px] text-slate-600">
                            {event.time}
                          </span>
                          {index < activityEvents.length - 1 ? null : (
                            <ChevronRight className="size-3 text-slate-700" />
                          )}
                        </div>
                      ))
                    ) : (
                      <p className="px-1 py-4 text-xs text-slate-600">
                        尚无可显示的审计事件。
                      </p>
                    )}
                  </CardContent>
                </Card>
              </div>

              <aside className="space-y-5">
                <Card className="border-cyan-300/10 bg-[linear-gradient(155deg,rgba(19,35,54,.96),rgba(13,23,38,.98))] ring-cyan-300/10">
                  <CardHeader className="border-b border-white/6 pb-4">
                    <div className="flex items-center gap-2">
                      <span
                        className={`size-2 rounded-full ${selected.status === 'online' ? 'bg-emerald-400' : selected.status === 'warning' ? 'bg-amber-400' : 'bg-slate-600'}`}
                      />
                      <CardTitle className="font-mono text-sm text-slate-100">
                        {selected.name}
                      </CardTitle>
                    </div>
                    <CardDescription className="font-mono text-[10px] text-slate-600">
                      {selected.address} · snapshot / latest
                    </CardDescription>
                    <CardAction>
                      <Button
                        variant="outline"
                        size="sm"
                        type="button"
                        onClick={() =>
                          document
                            .getElementById('operations-workspace')
                            ?.scrollIntoView({ behavior: 'smooth' })
                        }
                        title="前往受控 Web SSH 终端"
                        className="border-cyan-300/15 bg-cyan-300/8 text-cyan-200 hover:bg-cyan-300/15"
                      >
                        <TerminalSquare className="size-3.5" /> Web SSH
                      </Button>
                    </CardAction>
                  </CardHeader>
                  <CardContent className="space-y-5 pt-1">
                    {selected.fingerprint === 'pending' ? (
                      <div className="rounded-xl border border-amber-300/15 bg-amber-300/[0.055] p-4">
                        <div className="flex items-center gap-2 text-xs font-medium text-amber-200">
                          <Fingerprint className="size-4" />
                          主机指纹待确认
                        </div>
                        <p className="mt-2 text-[11px] leading-5 text-amber-100/55">
                          通过云厂商控制台核对 SHA-256
                          指纹后，才可启用命令和终端。
                        </p>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            void probeHostKey(selected.id, selected.version)
                          }
                          disabled={
                            dataMode !== 'live' ||
                            probingHostKey ||
                            selected.id === emptyHost.id
                          }
                          className="mt-3 border-amber-300/20 bg-amber-300/8 text-amber-100 hover:bg-amber-300/15"
                        >
                          <Fingerprint className="size-3.5" />
                          {probingHostKey ? '探测中…' : '获取待核对指纹'}
                        </Button>
                      </div>
                    ) : !selected.snapshotAvailable ? (
                      <div className="rounded-xl border border-cyan-300/12 bg-cyan-300/[0.045] p-4">
                        <div className="flex items-center gap-2 text-xs font-medium text-cyan-100">
                          <Activity className="size-4" />
                          尚无运行快照
                        </div>
                        <p className="mt-2 text-[11px] leading-5 text-cyan-100/50">
                          主机身份已固定。点击“刷新所选快照”后，控制面会创建受审计的只读采集任务。
                        </p>
                      </div>
                    ) : (
                      <>
                        <Progress value={selected.cpu}>
                          <ProgressLabel className="text-xs text-slate-400">
                            CPU
                          </ProgressLabel>
                          <ProgressValue className="font-mono text-xs text-slate-300">
                            {() => `${selected.cpu}%`}
                          </ProgressValue>
                        </Progress>
                        <Progress value={selected.memory}>
                          <ProgressLabel className="text-xs text-slate-400">
                            内存
                          </ProgressLabel>
                          <ProgressValue className="font-mono text-xs text-slate-300">
                            {() => `${selected.memory}%`}
                          </ProgressValue>
                        </Progress>
                        <Progress value={selected.disk}>
                          <ProgressLabel className="text-xs text-slate-400">
                            磁盘
                          </ProgressLabel>
                          <ProgressValue className="font-mono text-xs text-slate-300">
                            {() => `${selected.disk}%`}
                          </ProgressValue>
                        </Progress>
                        <div className="grid grid-cols-2 gap-2 pt-1">
                          <div className="rounded-lg border border-white/5 bg-white/[0.025] p-3">
                            <p className="text-[10px] text-slate-600">
                              LOAD 1M
                            </p>
                            <p className="mt-1 font-mono text-sm text-slate-200">
                              {selected.load}
                            </p>
                          </div>
                          <div className="rounded-lg border border-white/5 bg-white/[0.025] p-3">
                            <p className="text-[10px] text-slate-600">UPTIME</p>
                            <p className="mt-1 text-xs text-slate-200">
                              {selected.uptime}
                            </p>
                          </div>
                        </div>
                      </>
                    )}
                  </CardContent>
                </Card>

                <Card className="border-white/5 bg-[#101a2b]/88 ring-white/7">
                  <CardHeader>
                    <CardTitle className="text-sm text-slate-100">
                      快捷操作
                    </CardTitle>
                    <CardDescription className="text-xs text-slate-500">
                      所有操作均先经过权限与主机身份校验
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="grid grid-cols-2 gap-2">
                    {[
                      { label: '运行快照', icon: Activity },
                      { label: '安全扫描', icon: Radar },
                      { label: '执行命令', icon: Command },
                      { label: '服务状态', icon: Box },
                    ].map(({ label, icon: Icon }) => (
                      <button
                        key={label}
                        type="button"
                        onClick={() => {
                          if (label === '运行快照') {
                            void refreshSnapshots();
                            return;
                          }
                          document
                            .getElementById('operations-workspace')
                            ?.scrollIntoView({
                              behavior: 'smooth',
                              block: 'start',
                            });
                        }}
                        disabled={
                          selected.id === emptyHost.id ||
                          (label === '运行快照' &&
                            selected.fingerprint === 'pending')
                        }
                        className="flex items-center gap-2 rounded-lg border border-white/6 bg-white/[0.025] px-3 py-2.5 text-left text-xs text-slate-400 transition-colors hover:border-cyan-300/15 hover:bg-cyan-300/[0.055] hover:text-cyan-100 disabled:cursor-not-allowed disabled:opacity-35"
                      >
                        <Icon className="size-3.5 text-slate-500" />
                        {label}
                      </button>
                    ))}
                  </CardContent>
                </Card>

                <Card className="border-white/5 bg-[#101a2b]/88 ring-white/7">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-sm text-slate-100">
                      <Radar className="size-4 text-amber-300" />
                      风险摘要
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {selected.findings > 0 ? (
                      <div>
                        <p className="text-2xl font-semibold tracking-tight text-amber-200">
                          {selected.findings}
                        </p>
                        <p className="mt-1 text-xs leading-5 text-slate-500">
                          发现项均保留原始证据；当前不会自动终止进程或修改系统。
                        </p>
                      </div>
                    ) : (
                      <div className="flex items-start gap-3">
                        <ShieldCheck className="mt-0.5 size-4 text-emerald-300" />
                        <p className="text-xs leading-5 text-slate-500">
                          最近一次规则扫描未发现需处置项，这不代表主机已排除全部风险。
                        </p>
                      </div>
                    )}
                  </CardContent>
                </Card>

                <a
                  href="#support"
                  className="flex items-center justify-between rounded-xl border border-white/6 bg-white/[0.02] px-4 py-3 text-xs text-slate-500 transition-colors hover:bg-white/[0.04] hover:text-slate-300"
                >
                  <span className="flex items-center gap-2">
                    <LifeBuoy className="size-3.5" />
                    应急运维入口
                  </span>
                  <ChevronRight className="size-3.5" />
                </a>
              </aside>
            </div>
          </div>
          <OperationsWorkspace
            key={selected.id}
            host={{
              id: selected.id,
              name: selected.name,
              fingerprint: selected.fingerprint,
            }}
            live={dataMode === 'live'}
          />
        </section>
      </div>

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="border-white/8 bg-[#111d2f] text-slate-100 ring-white/10 sm:max-w-lg">
          <form onSubmit={addHost}>
            <DialogHeader>
              <DialogTitle>添加 VPS</DialogTitle>
              <DialogDescription className="text-slate-500">
                首次连接只获取 SSH 主机指纹；完成带外核对前不会执行命令。
              </DialogDescription>
            </DialogHeader>

            <div className="mt-5 grid gap-4 sm:grid-cols-2">
              <div className="sm:col-span-2">
                <label
                  htmlFor="host-name"
                  className="mb-1.5 block text-xs font-medium text-slate-400"
                >
                  主机名称
                </label>
                <Input
                  id="host-name"
                  value={newHost.name}
                  onChange={(event) =>
                    setNewHost((current) => ({
                      ...current,
                      name: event.target.value,
                    }))
                  }
                  placeholder="例如 edge-hkg-02"
                  required
                  maxLength={64}
                  className="h-9 border-white/8 bg-white/[0.035] text-slate-200"
                />
              </div>
              <div className="sm:col-span-2">
                <label
                  htmlFor="host-address"
                  className="mb-1.5 block text-xs font-medium text-slate-400"
                >
                  地址或域名
                </label>
                <Input
                  id="host-address"
                  value={newHost.address}
                  onChange={(event) =>
                    setNewHost((current) => ({
                      ...current,
                      address: event.target.value,
                    }))
                  }
                  placeholder="仅输入 IP 或主机名，不含协议和路径"
                  required
                  maxLength={253}
                  pattern="[A-Za-z0-9.:-]+"
                  className="h-9 border-white/8 bg-white/[0.035] font-mono text-slate-200"
                />
              </div>
              <div>
                <label
                  htmlFor="host-port"
                  className="mb-1.5 block text-xs font-medium text-slate-400"
                >
                  SSH 端口
                </label>
                <Input
                  id="host-port"
                  type="number"
                  min={1}
                  max={65535}
                  value={newHost.port}
                  onChange={(event) =>
                    setNewHost((current) => ({
                      ...current,
                      port: event.target.value,
                    }))
                  }
                  required
                  className="h-9 border-white/8 bg-white/[0.035] font-mono text-slate-200"
                />
              </div>
              <div>
                <label
                  htmlFor="host-username"
                  className="mb-1.5 block text-xs font-medium text-slate-400"
                >
                  SSH 用户
                </label>
                <Input
                  id="host-username"
                  value={newHost.username}
                  onChange={(event) =>
                    setNewHost((current) => ({
                      ...current,
                      username: event.target.value,
                    }))
                  }
                  required
                  maxLength={64}
                  pattern="[A-Za-z_][A-Za-z0-9_.-]*"
                  className="h-9 border-white/8 bg-white/[0.035] font-mono text-slate-200"
                />
              </div>
              <div>
                <label
                  htmlFor="host-region"
                  className="mb-1.5 block text-xs font-medium text-slate-400"
                >
                  区域标签
                </label>
                <NativeSelect
                  id="host-region"
                  value={newHost.region}
                  onChange={(event) =>
                    setNewHost((current) => ({
                      ...current,
                      region: event.target.value,
                    }))
                  }
                  className="w-full [&_select]:h-9 [&_select]:border-white/8 [&_select]:bg-white/[0.035] [&_select]:text-slate-200"
                >
                  {['香港', '新加坡', '东京', '法兰克福', '洛杉矶', '其他'].map(
                    (region) => (
                      <NativeSelectOption key={region} value={region}>
                        {region}
                      </NativeSelectOption>
                    ),
                  )}
                </NativeSelect>
              </div>
            </div>

            <div className="mt-5 rounded-lg border border-cyan-300/10 bg-cyan-300/[0.045] px-3 py-2.5 text-[11px] leading-5 text-cyan-100/55">
              目标地址仍会在控制面和 Connector
              两层执行网络策略校验，表单校验不能代替 SSRF 防护。
            </div>

            {formError ? (
              <p role="alert" className="mt-3 text-xs text-rose-300">
                {formError}
              </p>
            ) : null}

            <DialogFooter className="mt-5 border-white/7 bg-white/[0.025]">
              <Button
                type="button"
                variant="ghost"
                onClick={() => setAddOpen(false)}
                disabled={savingHost}
                className="text-slate-400 hover:bg-white/5"
              >
                取消
              </Button>
              <Button
                type="submit"
                disabled={savingHost}
                className="bg-cyan-300 text-slate-950 hover:bg-cyan-200"
              >
                {savingHost ? '保存中…' : '保存并获取指纹'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={hostKeyProbe !== null}
        onOpenChange={(open) => {
          if (!open && !pinningHostKey) {
            setHostKeyProbe(null);
            setConfirmedOutOfBand(false);
          }
        }}
      >
        <DialogContent className="border-white/8 bg-[#111d2f] text-slate-100 ring-white/10 sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>核对 SSH 主机指纹</DialogTitle>
            <DialogDescription className="text-slate-500">
              此结果来自当前网络握手，尚不可信。请在云厂商控制台或其他独立渠道核对后再固定。
            </DialogDescription>
          </DialogHeader>

          {hostKeyProbe ? (
            <div className="mt-5 space-y-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-lg border border-white/7 bg-white/[0.03] p-3">
                  <p className="text-[10px] uppercase tracking-wide text-slate-600">
                    ALGORITHM
                  </p>
                  <p className="mt-1 font-mono text-xs text-slate-200">
                    {hostKeyProbe.algorithm}
                  </p>
                </div>
                <div className="rounded-lg border border-white/7 bg-white/[0.03] p-3">
                  <p className="text-[10px] uppercase tracking-wide text-slate-600">
                    RESOLVED ADDRESS
                  </p>
                  <p className="mt-1 font-mono text-xs text-slate-200">
                    {hostKeyProbe.resolvedAddress}
                  </p>
                </div>
              </div>
              <div className="rounded-lg border border-cyan-300/12 bg-cyan-300/[0.045] p-3">
                <p className="text-[10px] uppercase tracking-wide text-cyan-100/45">
                  SHA-256 FINGERPRINT
                </p>
                <code className="mt-2 block break-all text-sm leading-6 text-cyan-100">
                  {hostKeyProbe.fingerprintSha256}
                </code>
              </div>
              <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-amber-300/15 bg-amber-300/[0.045] p-3 text-xs leading-5 text-amber-100/70">
                <input
                  type="checkbox"
                  checked={confirmedOutOfBand}
                  onChange={(event) =>
                    setConfirmedOutOfBand(event.target.checked)
                  }
                  className="mt-1 accent-cyan-300"
                />
                <span>
                  我已通过独立渠道核对，显示的算法、目标地址与 SHA-256
                  指纹完全一致。
                </span>
              </label>
            </div>
          ) : null}

          <DialogFooter className="mt-5 border-white/7 bg-white/[0.025]">
            <Button
              type="button"
              variant="ghost"
              onClick={() => setHostKeyProbe(null)}
              disabled={pinningHostKey}
              className="text-slate-400 hover:bg-white/5"
            >
              稍后核对
            </Button>
            <Button
              type="button"
              onClick={() => void pinHostKey()}
              disabled={!confirmedOutOfBand || pinningHostKey}
              className="bg-cyan-300 text-slate-950 hover:bg-cyan-200"
            >
              {pinningHostKey ? '固定中…' : '确认并固定指纹'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  );
}

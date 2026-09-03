'use client';

import { type SyntheticEvent, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  CloudCog,
  Command,
  Fingerprint,
  KeyRound,
  LoaderCircle,
  Play,
  Radar,
  ShieldCheck,
  SquareTerminal,
  Trash2,
  UploadCloud,
  Wrench,
} from 'lucide-react';

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  NativeSelect,
  NativeSelectOption,
} from '@/components/ui/native-select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import { pollControlPlaneJob } from '@/lib/job-poller';

import { RunbookWorkspace } from './runbook-workspace';
import { WebTerminal } from './web-terminal';

type CredentialMetadata = {
  id: string;
  hostId: string;
  kind: string;
  publicKeyFingerprint: string;
  keyId: string;
  createdAt: string;
  createdBy: string;
};

type CommandResult = {
  commandId: string;
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMillis: number;
  truncated: boolean;
};

type Finding = {
  id: string;
  ruleId: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  evidence: Record<string, unknown>;
  falsePositiveNote: string;
};

type AIOutcome = {
  mode: 'gateway' | 'rules_fallback';
  fallbackReason?: string;
  analysis: {
    schemaVersion: 'vpsmanager.ai-analysis.v1';
    summary: string;
    rankedFindings: Array<{
      findingId: string;
      rank: number;
      rationale: string;
    }>;
    humanVerificationSteps: Array<{
      findingId: string;
      description: string;
    }>;
    recommendations: Array<{
      findingId: string;
      priority: string;
      advice: string;
    }>;
    executionAllowed: false;
  };
};

type OperationJob = {
  id: string;
  state:
    | 'queued'
    | 'running'
    | 'succeeded'
    | 'failed'
    | 'timed_out'
    | 'cancelled';
  commandResult?: CommandResult;
  anomalyScan?: {
    observedAt: string;
    engine: string;
    aiExecutionAllowed: false;
    processesEvaluated: number;
    findings: Finding[];
    aiAnalysis?: AIOutcome;
  };
  error?: { message?: string };
};

type WorkerProject = {
  id: string;
  name: string;
  accountId: string;
  scriptName: string;
  desiredVersionId?: string;
};

type WorkerTokenMetadata = {
  id?: string;
  createdAt?: string;
  kind?: string;
};

type WorkerVersion = {
  id: string;
  createdAt?: string;
  contentDigest?: string;
  providerVersionId?: string;
};

type WorkerDeployment = {
  id: string;
  versionId: string;
  kind: 'deploy' | 'rollback';
  state: string;
  providerExecutionAllowed: boolean;
  providerVersionId?: string;
  providerDeploymentId?: string;
  providerState?: string;
  errorCode?: string;
};

type OperationsHost = {
  id: string;
  name: string;
  fingerprint: 'verified' | 'pending';
};

const commandLabels: Record<string, string> = {
  disk_usage_v1: '磁盘使用情况',
  listening_ports_v1: '监听端口',
  service_status_v1: '服务状态',
};

const demoFindings: Finding[] = [
  {
    id: 'demo-finding-1',
    ruleId: 'unexpected_listener_v1',
    title: '发现非基线监听端口',
    severity: 'medium',
    confidence: 0.82,
    evidence: { process: 'node', port: 47821, user: 'www-data' },
    falsePositiveNote: '临时调试服务可能产生该特征，请结合发布记录核对。',
  },
  {
    id: 'demo-finding-2',
    ruleId: 'high_cpu_process_v1',
    title: '进程持续高 CPU',
    severity: 'high',
    confidence: 0.91,
    evidence: { process: 'node', cpuPercent: 68, elapsed: '14m' },
    falsePositiveNote: '构建、压缩或批处理任务可能属于正常业务负载。',
  },
];

const demoCommandResult: CommandResult = {
  commandId: 'disk_usage_v1',
  stdout:
    'Filesystem      Size  Used Avail Use% Mounted on\n/dev/vda1        80G   34G   43G  45% /',
  stderr: '',
  exitCode: 0,
  durationMillis: 184,
  truncated: false,
};

const helloWorker = `export default {
  async fetch() {
    return new Response("Hello from VPS Control Plane");
  },
};`;

export function OperationsWorkspace({
  host,
  live,
}: {
  host: OperationsHost;
  live: boolean;
}) {
  const [credential, setCredential] = useState<CredentialMetadata | null>(null);
  const [credentialState, setCredentialState] = useState<
    'loading' | 'present' | 'missing' | 'offline'
  >('offline');
  const [credentialEditorOpen, setCredentialEditorOpen] = useState(false);
  const [privateKey, setPrivateKey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [credentialBusy, setCredentialBusy] = useState(false);
  const [commandId, setCommandId] = useState('disk_usage_v1');
  const [serviceName, setServiceName] = useState('nginx');
  const [commandBusy, setCommandBusy] = useState(false);
  const [commandResult, setCommandResult] = useState<CommandResult | null>(
    live ? null : demoCommandResult,
  );
  const [scanBusy, setScanBusy] = useState(false);
  const [scanFindings, setScanFindings] = useState<Finding[]>(
    live ? [] : demoFindings,
  );
  const [scanMeta, setScanMeta] = useState<{
    processesEvaluated: number;
    observedAt: string;
  } | null>(null);
  const [aiOutcome, setAIOutcome] = useState<AIOutcome | null>(null);
  const [notice, setNotice] = useState('');
  const [workers, setWorkers] = useState<WorkerProject[]>([]);
  const [workerId, setWorkerId] = useState('');
  const [workerForm, setWorkerForm] = useState({
    name: '',
    accountId: '',
    scriptName: '',
  });
  const [workerBusy, setWorkerBusy] = useState(false);
  const [workerToken, setWorkerToken] = useState('');
  const [workerTokenMetadata, setWorkerTokenMetadata] =
    useState<WorkerTokenMetadata | null>(null);
  const [workerSource, setWorkerSource] = useState(helloWorker);
  const [deploymentVersionId, setDeploymentVersionId] = useState('');
  const [versions, setVersions] = useState<WorkerVersion[]>([]);
  const [deployments, setDeployments] = useState<WorkerDeployment[]>([]);

  const selectedWorker = useMemo(
    () => workers.find((worker) => worker.id === workerId) ?? null,
    [workerId, workers],
  );
  const selectedVersion = useMemo(
    () =>
      versions.find((version) => version.id === deploymentVersionId) ?? null,
    [deploymentVersionId, versions],
  );
  const deploymentPending = deployments.some((deployment) =>
    ['ready_for_provider', 'running'].includes(deployment.state),
  );
  const hostReady =
    live && host.id !== 'empty' && host.fingerprint === 'verified';
  const sshReady = hostReady && credentialState === 'present';

  useEffect(() => {
    const controller = new AbortController();
    void Promise.resolve().then(() => {
      if (controller.signal.aborted) return;
      setCredential(null);
      setCommandResult(live ? null : demoCommandResult);
      setScanFindings(live ? [] : demoFindings);
      setScanMeta(null);
      setAIOutcome(null);
      setNotice('');
      setCredentialState(!live || host.id === 'empty' ? 'offline' : 'loading');
    });

    if (!live || host.id === 'empty') {
      return () => controller.abort();
    }

    void fetch(
      `/api/control-plane/hosts/${encodeURIComponent(host.id)}/credential`,
      { cache: 'no-store', signal: controller.signal },
    )
      .then(async (response) => {
        if (response.status === 404) {
          setCredentialState('missing');
          return;
        }
        if (!response.ok)
          throw new Error(await apiError(response, '无法读取凭据状态'));
        const metadata = (await response.json()) as CredentialMetadata;
        setCredential(metadata);
        setCredentialState('present');
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === 'AbortError')
          return;
        setCredentialState('missing');
        setNotice(error instanceof Error ? error.message : '无法读取凭据状态');
      });

    return () => controller.abort();
  }, [host.id, live]);

  useEffect(() => {
    const controller = new AbortController();
    if (!live) {
      void Promise.resolve().then(() => {
        if (controller.signal.aborted) return;
        setWorkers([]);
        setWorkerId('');
      });
      return () => controller.abort();
    }

    void fetch('/api/control-plane/cloudflare/workers', {
      cache: 'no-store',
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) throw new Error('无法读取 Worker 项目');
        const payload = (await response.json()) as { items?: WorkerProject[] };
        const items = Array.isArray(payload.items) ? payload.items : [];
        setWorkers(items);
        setWorkerId((current) =>
          items.some((item) => item.id === current)
            ? current
            : (items[0]?.id ?? ''),
        );
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === 'AbortError')
          return;
        setWorkers([]);
      });

    return () => controller.abort();
  }, [live]);

  useEffect(() => {
    const controller = new AbortController();
    void Promise.resolve().then(() => {
      if (controller.signal.aborted) return;
      setWorkerTokenMetadata(null);
      setVersions([]);
      setDeploymentVersionId('');
      setDeployments([]);
    });
    if (!live || !workerId) return () => controller.abort();

    const base = `/api/control-plane/cloudflare/workers/${encodeURIComponent(workerId)}`;
    void Promise.all([
      fetch(`${base}/token`, {
        cache: 'no-store',
        signal: controller.signal,
      }),
      fetch(`${base}/versions`, {
        cache: 'no-store',
        signal: controller.signal,
      }),
      fetch(`${base}/deployments`, {
        cache: 'no-store',
        signal: controller.signal,
      }),
    ])
      .then(async ([tokenResponse, versionResponse, deploymentResponse]) => {
        if (tokenResponse.ok) {
          setWorkerTokenMetadata(
            (await tokenResponse.json()) as WorkerTokenMetadata,
          );
        }
        if (versionResponse.ok) {
          const payload = (await versionResponse.json()) as {
            items?: WorkerVersion[];
          };
          const items = Array.isArray(payload.items) ? payload.items : [];
          setVersions(items);
          setDeploymentVersionId((current) =>
            items.some((item) => item.id === current)
              ? current
              : (items[0]?.id ?? ''),
          );
        }
        if (deploymentResponse.ok) {
          const payload = (await deploymentResponse.json()) as {
            items?: WorkerDeployment[];
          };
          setDeployments(Array.isArray(payload.items) ? payload.items : []);
        }
      })
      .catch(() => undefined);

    return () => controller.abort();
  }, [live, workerId]);

  async function saveCredential(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!hostReady) return;
    setCredentialBusy(true);
    setNotice('');
    try {
      const response = await fetch(
        `/api/control-plane/hosts/${encodeURIComponent(host.id)}/credential`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ privateKey, passphrase }),
        },
      );
      if (!response.ok) {
        throw new Error(await apiError(response, '控制面拒绝了 SSH 凭据'));
      }
      const metadata = (await response.json()) as CredentialMetadata;
      setCredential(metadata);
      setCredentialState('present');
      setCredentialEditorOpen(false);
      setNotice('SSH 私钥已加密保存；浏览器不会再次显示私钥内容。');
    } catch (error) {
      setNotice(error instanceof Error ? error.message : '保存 SSH 凭据失败');
    } finally {
      setPrivateKey('');
      setPassphrase('');
      setCredentialBusy(false);
    }
  }

  async function removeCredential() {
    if (!live || host.id === 'empty') return;
    setCredentialBusy(true);
    setNotice('');
    try {
      const response = await fetch(
        `/api/control-plane/hosts/${encodeURIComponent(host.id)}/credential`,
        { method: 'DELETE' },
      );
      if (!response.ok) {
        throw new Error(await apiError(response, '无法删除 SSH 凭据'));
      }
      setCredential(null);
      setCredentialState('missing');
      setNotice('SSH 凭据已删除，新的 SSH 任务将被阻断。');
    } catch (error) {
      setNotice(error instanceof Error ? error.message : '删除 SSH 凭据失败');
    } finally {
      setCredentialBusy(false);
    }
  }

  async function executeCommand() {
    if (!sshReady) return;
    setCommandBusy(true);
    setCommandResult(null);
    setNotice('');
    try {
      const parameters =
        commandId === 'service_status_v1' ? { service: serviceName } : {};
      const response = await fetch(
        `/api/control-plane/hosts/${encodeURIComponent(host.id)}/commands`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ commandId, parameters }),
        },
      );
      if (!response.ok) {
        throw new Error(await apiError(response, '无法创建命令任务'));
      }
      const created = (await response.json()) as OperationJob;
      const finished = await pollControlPlaneJob<OperationJob>(created.id);
      if (finished.state !== 'succeeded' || !finished.commandResult) {
        throw new Error(
          finished.error?.message ?? `命令任务状态：${finished.state}`,
        );
      }
      setCommandResult(finished.commandResult);
      setNotice('预定义只读命令已执行并记录审计事件。');
    } catch (error) {
      setNotice(error instanceof Error ? error.message : '命令任务失败');
    } finally {
      setCommandBusy(false);
    }
  }

  async function runAnomalyScan() {
    if (!sshReady) return;
    setScanBusy(true);
    setScanFindings([]);
    setScanMeta(null);
    setAIOutcome(null);
    setNotice('');
    try {
      const response = await fetch(
        `/api/control-plane/hosts/${encodeURIComponent(host.id)}/anomaly-scans`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: '{}',
        },
      );
      if (!response.ok) {
        throw new Error(await apiError(response, '无法创建异常扫描任务'));
      }
      const created = (await response.json()) as OperationJob;
      const finished = await pollControlPlaneJob<OperationJob>(created.id);
      if (finished.state !== 'succeeded' || !finished.anomalyScan) {
        throw new Error(
          finished.error?.message ?? `扫描任务状态：${finished.state}`,
        );
      }
      setScanFindings(finished.anomalyScan.findings);
      setScanMeta({
        processesEvaluated: finished.anomalyScan.processesEvaluated,
        observedAt: finished.anomalyScan.observedAt,
      });
      setAIOutcome(finished.anomalyScan.aiAnalysis ?? null);
      setNotice('规则扫描已完成；结果只提供证据和建议，不会自动处置。');
    } catch (error) {
      setNotice(error instanceof Error ? error.message : '异常扫描失败');
    } finally {
      setScanBusy(false);
    }
  }

  async function createWorker(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!live) return;
    setWorkerBusy(true);
    setNotice('');
    try {
      const response = await fetch('/api/control-plane/cloudflare/workers', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(workerForm),
      });
      if (!response.ok) {
        throw new Error(await apiError(response, '无法创建 Worker 项目'));
      }
      const worker = (await response.json()) as WorkerProject;
      setWorkers((current) => [worker, ...current]);
      setWorkerId(worker.id);
      setWorkerForm({ name: '', accountId: '', scriptName: '' });
      setNotice('Worker 项目已创建；尚未调用 Cloudflare 发布接口。');
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : '创建 Worker 项目失败',
      );
    } finally {
      setWorkerBusy(false);
    }
  }

  async function saveWorkerToken() {
    if (!live || !workerId || !workerToken) return;
    setWorkerBusy(true);
    setNotice('');
    try {
      const response = await fetch(
        `/api/control-plane/cloudflare/workers/${encodeURIComponent(workerId)}/token`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ token: workerToken }),
        },
      );
      if (!response.ok) {
        throw new Error(await apiError(response, '无法保存 Cloudflare Token'));
      }
      setWorkerTokenMetadata((await response.json()) as WorkerTokenMetadata);
      setNotice('Cloudflare Token 已加密保存且不会回显。');
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : '保存 Cloudflare Token 失败',
      );
    } finally {
      setWorkerToken('');
      setWorkerBusy(false);
    }
  }

  async function createWorkerVersion() {
    if (!live || !workerId) return;
    const moduleBytes = new TextEncoder().encode(workerSource).byteLength;
    if (moduleBytes > 256 * 1024) {
      setNotice('Worker 模块超过 256 KiB 安全上限，请先完成预构建和精简。');
      return;
    }
    setWorkerBusy(true);
    setNotice('');
    try {
      const response = await fetch(
        `/api/control-plane/cloudflare/workers/${encodeURIComponent(workerId)}/versions`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            moduleBase64: utf8Base64(workerSource),
            contentType: 'application/javascript',
            entrypoint: 'index.js',
          }),
        },
      );
      if (!response.ok) {
        throw new Error(await apiError(response, '无法保存 Worker 版本'));
      }
      const version = (await response.json()) as WorkerVersion;
      setVersions((current) => [version, ...current]);
      setDeploymentVersionId(version.id);
      setNotice('Worker 预构建模块版本已保存；还没有生产发布。');
    } catch (error) {
      setNotice(
        error instanceof Error ? error.message : '保存 Worker 版本失败',
      );
    } finally {
      setWorkerBusy(false);
    }
  }

  async function planDeployment(kind: 'deploy' | 'rollback') {
    const version = selectedVersion;
    if (!live || !workerId || !version) return;
    setWorkerBusy(true);
    setNotice('');
    try {
      const response = await fetch(
        `/api/control-plane/cloudflare/workers/${encodeURIComponent(workerId)}/deployments`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ versionId: version.id, kind }),
        },
      );
      if (!response.ok) {
        throw new Error(await apiError(response, '无法创建部署计划'));
      }
      const deployment = (await response.json()) as WorkerDeployment;
      setDeployments((current) => [deployment, ...current]);
      setWorkers((current) =>
        current.map((worker) =>
          worker.id === workerId
            ? { ...worker, desiredVersionId: version.id }
            : worker,
        ),
      );
      setNotice('部署计划已记录；确认后可调用 Cloudflare Provider 执行。');
    } catch (error) {
      setNotice(error instanceof Error ? error.message : '创建部署计划失败');
    } finally {
      setWorkerBusy(false);
    }
  }

  async function executeDeployment() {
    const deployment = deployments[0];
    if (!live || !workerId || deployment?.state !== 'ready_for_provider')
      return;
    setWorkerBusy(true);
    setNotice('');
    try {
      const response = await fetch(
        `/api/control-plane/cloudflare/workers/${encodeURIComponent(workerId)}/deployments/${encodeURIComponent(deployment.id)}/execute`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: '{}',
        },
      );
      if (!response.ok) {
        throw new Error(await apiError(response, 'Cloudflare 发布执行失败'));
      }
      const updated = (await response.json()) as WorkerDeployment;
      setDeployments((current) =>
        current.map((item) => (item.id === updated.id ? updated : item)),
      );
      if (updated.providerVersionId) {
        setVersions((current) =>
          current.map((version) =>
            version.id === updated.versionId
              ? { ...version, providerVersionId: updated.providerVersionId }
              : version,
          ),
        );
      }
      setNotice(
        updated.state === 'succeeded'
          ? 'Cloudflare Worker 已发布，Provider 状态已写入审计。'
          : `Cloudflare 发布状态：${updated.state}`,
      );
    } catch (error) {
      const refreshed = await fetch(
        `/api/control-plane/cloudflare/workers/${encodeURIComponent(workerId)}/deployments`,
        { cache: 'no-store' },
      ).catch(() => null);
      if (refreshed?.ok) {
        const payload = (await refreshed.json()) as {
          items?: WorkerDeployment[];
        };
        setDeployments(Array.isArray(payload.items) ? payload.items : []);
      }
      setNotice(
        error instanceof Error ? error.message : 'Cloudflare 发布执行失败',
      );
    } finally {
      setWorkerBusy(false);
    }
  }

  return (
    <section
      id="operations-workspace"
      className="border-t border-white/6 bg-[#0b1322]/70 px-4 py-7 sm:px-6 xl:px-8"
    >
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-cyan-300/65">
              controlled operations / m1
            </p>
            <Badge
              variant="outline"
              className={
                live
                  ? 'border-emerald-300/20 text-emerald-300'
                  : 'border-amber-300/20 text-amber-300'
              }
            >
              {live ? 'CONTROL PLANE' : 'DEMO ONLY'}
            </Badge>
          </div>
          <h2 className="mt-2 text-xl font-semibold tracking-tight text-slate-100">
            凭据、终端、命令、扫描与 Workers
          </h2>
          <p className="mt-1 text-xs leading-5 text-slate-500">
            当前目标：{host.name}。只读 SSH 操作必须同时具备固定指纹和加密凭据。
          </p>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-slate-500">
          <ShieldCheck className="size-4 text-emerald-300" />
          终端一次性票据 · 无自动杀进程 · 生产发布需确认
        </div>
      </div>

      {notice ? (
        <output className="mb-4 block rounded-lg border border-cyan-300/12 bg-cyan-300/[0.045] px-3 py-2 text-xs text-cyan-100/70">
          {notice}
        </output>
      ) : null}

      <Tabs defaultValue="credentials">
        <TabsList
          variant="line"
          className="w-full justify-start overflow-x-auto border-b border-white/7"
        >
          <TabsTrigger value="credentials">
            <KeyRound /> 凭据
          </TabsTrigger>
          <TabsTrigger value="commands">
            <Command /> 只读命令
          </TabsTrigger>
          <TabsTrigger value="runbooks">
            <Wrench /> 配置 / 应急
          </TabsTrigger>
          <TabsTrigger value="terminal">
            <SquareTerminal /> Web SSH
          </TabsTrigger>
          <TabsTrigger value="scan">
            <Radar /> 异常扫描
          </TabsTrigger>
          <TabsTrigger value="workers">
            <CloudCog /> Workers
          </TabsTrigger>
        </TabsList>

        <TabsContent value="credentials" className="pt-5">
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(320px,.82fr)]">
            <Card className="border-white/6 bg-[#101a2b]/88 ring-white/7">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm text-slate-100">
                  <Fingerprint className="size-4 text-cyan-300" />
                  {host.name} 的 SSH 身份链
                </CardTitle>
                <CardDescription className="text-xs text-slate-500">
                  私钥只写入控制面密钥层，GET 接口仅返回不可用的元数据。
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <StatusRow
                  label="主机指纹"
                  value={
                    host.fingerprint === 'verified' ? '已固定' : '等待带外核对'
                  }
                  ready={host.fingerprint === 'verified'}
                />
                <StatusRow
                  label="SSH 凭据"
                  value={
                    credentialState === 'present'
                      ? '已加密保存'
                      : credentialState === 'loading'
                        ? '读取中'
                        : credentialState === 'offline'
                          ? '演示模式不接收密钥'
                          : '尚未配置'
                  }
                  ready={credentialState === 'present'}
                />
                {credential ? (
                  <div className="rounded-lg border border-white/6 bg-white/[0.025] p-3">
                    <p className="text-[10px] uppercase tracking-wide text-slate-600">
                      PUBLIC KEY FINGERPRINT
                    </p>
                    <code className="mt-2 block break-all text-xs leading-5 text-slate-300">
                      {credential.publicKeyFingerprint}
                    </code>
                    <p className="mt-2 text-[10px] text-slate-600">
                      KMS key {credential.keyId} ·{' '}
                      {formatTime(credential.createdAt)}
                    </p>
                  </div>
                ) : null}
                <div className="flex flex-wrap gap-2 pt-1">
                  <Button
                    type="button"
                    onClick={() => setCredentialEditorOpen((value) => !value)}
                    disabled={!hostReady || credentialBusy}
                    className="bg-cyan-300 text-slate-950 hover:bg-cyan-200"
                  >
                    <UploadCloud />
                    {credential ? '轮换凭据' : '配置凭据'}
                  </Button>
                  {credential ? (
                    <AlertDialog>
                      <AlertDialogTrigger
                        render={
                          <Button
                            variant="destructive"
                            disabled={credentialBusy}
                          />
                        }
                      >
                        <Trash2 /> 删除凭据
                      </AlertDialogTrigger>
                      <AlertDialogContent className="border-white/8 bg-[#111d2f] text-slate-100">
                        <AlertDialogHeader>
                          <AlertDialogTitle>删除 SSH 凭据？</AlertDialogTitle>
                          <AlertDialogDescription>
                            删除后，运行快照、只读命令和异常扫描都会立即被阻断。
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>取消</AlertDialogCancel>
                          <AlertDialogAction
                            variant="destructive"
                            onClick={() => void removeCredential()}
                          >
                            确认删除
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  ) : null}
                </div>
              </CardContent>
            </Card>

            <Card className="border-white/6 bg-[#101a2b]/88 ring-white/7">
              <CardHeader>
                <CardTitle className="text-sm text-slate-100">
                  {credentialEditorOpen ? '上传或轮换私钥' : '凭据安全边界'}
                </CardTitle>
                <CardDescription className="text-xs text-slate-500">
                  {credentialEditorOpen
                    ? '提交完成后，表单会立即清空。'
                    : '线上演示模式不会接受或保存任何私钥。'}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {credentialEditorOpen ? (
                  <form className="space-y-3" onSubmit={saveCredential}>
                    <label
                      htmlFor="ssh-private-key"
                      className="block text-xs text-slate-400"
                    >
                      OpenSSH / PEM 私钥
                      <Textarea
                        id="ssh-private-key"
                        value={privateKey}
                        onChange={(event) => setPrivateKey(event.target.value)}
                        required
                        maxLength={262_144}
                        spellCheck={false}
                        autoComplete="off"
                        className="mt-1.5 min-h-40 border-white/8 bg-black/20 font-mono text-xs text-slate-200"
                        placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                      />
                    </label>
                    <label
                      htmlFor="ssh-key-passphrase"
                      className="block text-xs text-slate-400"
                    >
                      私钥口令（可选）
                      <Input
                        id="ssh-key-passphrase"
                        type="password"
                        value={passphrase}
                        onChange={(event) => setPassphrase(event.target.value)}
                        maxLength={4096}
                        autoComplete="new-password"
                        className="mt-1.5 border-white/8 bg-black/20"
                      />
                    </label>
                    <Button
                      type="submit"
                      disabled={credentialBusy || !privateKey}
                      className="w-full bg-cyan-300 text-slate-950 hover:bg-cyan-200"
                    >
                      {credentialBusy ? (
                        <LoaderCircle className="animate-spin" />
                      ) : (
                        <KeyRound />
                      )}
                      加密保存
                    </Button>
                  </form>
                ) : (
                  <ul className="space-y-3 text-xs leading-5 text-slate-500">
                    <li>• 服务端解析私钥并只保留公钥指纹作为可见元数据。</li>
                    <li>• 每份密文绑定 Host、Credential ID 和版本上下文。</li>
                    <li>
                      • Connector 仅在获授权任务执行时短暂解密并立即释放。
                    </li>
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="commands" className="pt-5">
          <div className="grid gap-4 lg:grid-cols-[360px_minmax(0,1fr)]">
            <Card className="border-white/6 bg-[#101a2b]/88 ring-white/7">
              <CardHeader>
                <CardTitle className="text-sm text-slate-100">
                  预定义只读命令
                </CardTitle>
                <CardDescription className="text-xs text-slate-500">
                  浏览器不能提交 executable、flags 或 Shell 文本。
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <label className="block text-xs text-slate-400">
                  命令模板
                  <NativeSelect
                    value={commandId}
                    onChange={(event) => setCommandId(event.target.value)}
                    className="mt-1.5 w-full [&_select]:border-white/8 [&_select]:bg-white/[0.035]"
                  >
                    {Object.entries(commandLabels).map(([value, label]) => (
                      <NativeSelectOption key={value} value={value}>
                        {label}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                </label>
                {commandId === 'service_status_v1' ? (
                  <label className="block text-xs text-slate-400">
                    允许的服务
                    <NativeSelect
                      value={serviceName}
                      onChange={(event) => setServiceName(event.target.value)}
                      className="mt-1.5 w-full [&_select]:border-white/8 [&_select]:bg-white/[0.035]"
                    >
                      {['nginx', 'ssh', 'docker', 'cron'].map((service) => (
                        <NativeSelectOption key={service} value={service}>
                          {service}
                        </NativeSelectOption>
                      ))}
                    </NativeSelect>
                  </label>
                ) : null}
                <Button
                  type="button"
                  onClick={() => void executeCommand()}
                  disabled={!sshReady || commandBusy}
                  className="w-full bg-cyan-300 text-slate-950 hover:bg-cyan-200"
                >
                  {commandBusy ? (
                    <LoaderCircle className="animate-spin" />
                  ) : (
                    <Play />
                  )}
                  创建受审计任务
                </Button>
                {!sshReady ? (
                  <p className="text-[11px] leading-5 text-amber-200/60">
                    需要连接控制面、固定主机指纹并配置 SSH 凭据。
                  </p>
                ) : null}
              </CardContent>
            </Card>

            <Card className="min-w-0 border-white/6 bg-[#0b1322] ring-white/7">
              <CardHeader>
                <CardTitle className="flex items-center justify-between text-sm text-slate-100">
                  输出
                  {!live ? (
                    <Badge
                      variant="outline"
                      className="border-amber-300/20 text-amber-300"
                    >
                      DEMO RESULT
                    </Badge>
                  ) : null}
                </CardTitle>
                <CardDescription className="text-xs text-slate-500">
                  {commandResult
                    ? `exit ${commandResult.exitCode} · ${commandResult.durationMillis} ms`
                    : '尚未执行任务'}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <pre className="min-h-48 overflow-auto rounded-lg border border-white/6 bg-black/30 p-4 font-mono text-xs leading-6 text-emerald-200/80">
                  {commandResult?.stdout ??
                    '选择模板后创建任务；输出会受长度上限和超时策略保护。'}
                  {commandResult?.stderr
                    ? `\n[stderr]\n${commandResult.stderr}`
                    : ''}
                </pre>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="runbooks" className="pt-5">
          <RunbookWorkspace
            key={host.id}
            hostId={host.id}
            hostName={host.name}
            enabled={sshReady}
            live={live}
          />
        </TabsContent>

        <TabsContent value="terminal" className="pt-5">
          <WebTerminal
            key={host.id}
            hostId={host.id}
            hostName={host.name}
            enabled={sshReady}
          />
        </TabsContent>

        <TabsContent value="scan" className="pt-5">
          <Card className="border-white/6 bg-[#101a2b]/88 ring-white/7">
            <CardHeader className="sm:flex-row sm:items-center sm:justify-between">
              <div>
                <CardTitle className="flex items-center gap-2 text-sm text-slate-100">
                  <Radar className="size-4 text-amber-300" />
                  进程启发式扫描
                </CardTitle>
                <CardDescription className="mt-1 text-xs text-slate-500">
                  规则先生成证据；AI 仅可解释，不能执行命令或自动处置。
                </CardDescription>
              </div>
              <Button
                type="button"
                onClick={() => void runAnomalyScan()}
                disabled={!sshReady || scanBusy}
                className="mt-3 bg-amber-300 text-slate-950 hover:bg-amber-200 sm:mt-0"
              >
                {scanBusy ? (
                  <LoaderCircle className="animate-spin" />
                ) : (
                  <Radar />
                )}
                扫描所选主机
              </Button>
            </CardHeader>
            <CardContent>
              <div className="mb-3 flex flex-wrap gap-2 text-[11px] text-slate-500">
                <Badge variant="outline">rules_v1</Badge>
                <Badge variant="outline">AI EXECUTION: DENIED</Badge>
                {scanMeta ? (
                  <span>
                    {scanMeta.processesEvaluated} 个进程 ·{' '}
                    {formatTime(scanMeta.observedAt)}
                  </span>
                ) : null}
              </div>
              <div className="grid gap-3 lg:grid-cols-2">
                {scanFindings.length ? (
                  scanFindings.map((finding) => (
                    <FindingCard key={finding.id} finding={finding} />
                  ))
                ) : (
                  <div className="col-span-full flex items-start gap-3 rounded-lg border border-emerald-300/10 bg-emerald-300/[0.035] p-4">
                    <CheckCircle2 className="mt-0.5 size-4 text-emerald-300" />
                    <p className="text-xs leading-5 text-slate-500">
                      当前没有扫描结果。没有发现项不等于已排除全部入侵风险。
                    </p>
                  </div>
                )}
              </div>
              {aiOutcome ? (
                <div className="mt-4 border-t border-white/6 pt-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-xs font-semibold text-slate-200">
                      AI / 规则降级解读
                    </p>
                    <Badge variant="outline">
                      {aiOutcome.mode === 'gateway'
                        ? 'AI GATEWAY'
                        : 'RULES FALLBACK'}
                    </Badge>
                    <Badge variant="outline">EXECUTION DENIED</Badge>
                  </div>
                  <p className="mt-2 text-xs leading-6 text-slate-400">
                    {aiOutcome.analysis.summary}
                  </p>
                  <div className="mt-3 grid gap-2 lg:grid-cols-2">
                    {aiOutcome.analysis.recommendations
                      .slice(0, 6)
                      .map((item) => (
                        <div
                          key={`${item.findingId}-${item.priority}`}
                          className="rounded-lg border border-white/6 bg-black/15 p-3"
                        >
                          <p className="font-mono text-[10px] text-cyan-300/70">
                            {item.findingId} · {item.priority}
                          </p>
                          <p className="mt-1 text-[11px] leading-5 text-slate-500">
                            {item.advice}
                          </p>
                        </div>
                      ))}
                  </div>
                  <p className="mt-3 text-[10px] leading-5 text-slate-600">
                    仅供人工核验；模型无 SSH、Vault、部署或处置权限。
                    {aiOutcome.fallbackReason
                      ? ` 降级原因：${aiOutcome.fallbackReason}`
                      : ''}
                  </p>
                </div>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="workers" className="pt-5">
          <div className="grid gap-4 xl:grid-cols-[340px_minmax(0,1fr)]">
            <Card className="border-white/6 bg-[#101a2b]/88 ring-white/7">
              <CardHeader>
                <CardTitle className="text-sm text-slate-100">
                  Worker 项目
                </CardTitle>
                <CardDescription className="text-xs text-slate-500">
                  当前阶段仅保存版本和部署计划，不调用 Provider。
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {workers.length ? (
                  <NativeSelect
                    value={workerId}
                    onChange={(event) => {
                      setWorkerToken('');
                      setWorkerId(event.target.value);
                    }}
                    disabled={workerBusy}
                    className="w-full [&_select]:border-white/8 [&_select]:bg-white/[0.035]"
                  >
                    {workers.map((worker) => (
                      <NativeSelectOption key={worker.id} value={worker.id}>
                        {worker.name} / {worker.scriptName}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                ) : null}
                <form className="space-y-2" onSubmit={createWorker}>
                  <Input
                    value={workerForm.name}
                    onChange={(event) =>
                      setWorkerForm((current) => ({
                        ...current,
                        name: event.target.value,
                      }))
                    }
                    placeholder="项目名称"
                    required
                    maxLength={100}
                    disabled={!live}
                    className="border-white/8 bg-white/[0.035]"
                  />
                  <Input
                    value={workerForm.accountId}
                    onChange={(event) =>
                      setWorkerForm((current) => ({
                        ...current,
                        accountId: event.target.value.trim(),
                      }))
                    }
                    placeholder="32 位 Cloudflare Account ID"
                    required
                    pattern="[A-Fa-f0-9]{32}"
                    disabled={!live}
                    className="border-white/8 bg-white/[0.035] font-mono"
                  />
                  <Input
                    value={workerForm.scriptName}
                    onChange={(event) =>
                      setWorkerForm((current) => ({
                        ...current,
                        scriptName: event.target.value,
                      }))
                    }
                    placeholder="worker-script-name"
                    required
                    pattern="[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                    disabled={!live}
                    className="border-white/8 bg-white/[0.035] font-mono"
                  />
                  <Button
                    type="submit"
                    variant="outline"
                    disabled={!live || workerBusy}
                    className="w-full border-cyan-300/15 text-cyan-200"
                  >
                    创建项目
                  </Button>
                </form>
              </CardContent>
            </Card>

            <div className="grid gap-4 lg:grid-cols-2">
              <Card className="border-white/6 bg-[#101a2b]/88 ring-white/7">
                <CardHeader>
                  <CardTitle className="text-sm text-slate-100">
                    Token 与版本
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-500">
                    Token 加密后不可回显；模块作为预构建 ES Module 保存。
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    {workerTokenMetadata ? (
                      <CheckCircle2 className="size-4 text-emerald-300" />
                    ) : (
                      <AlertTriangle className="size-4 text-amber-300" />
                    )}
                    {workerTokenMetadata
                      ? 'Token 已加密保存'
                      : '尚未配置 Token'}
                  </div>
                  <Input
                    type="password"
                    value={workerToken}
                    onChange={(event) => setWorkerToken(event.target.value)}
                    placeholder="Cloudflare API Token"
                    maxLength={512}
                    autoComplete="new-password"
                    disabled={!selectedWorker || !live}
                    className="border-white/8 bg-black/20"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void saveWorkerToken()}
                    disabled={
                      !selectedWorker || !live || !workerToken || workerBusy
                    }
                    className="w-full border-cyan-300/15 text-cyan-200"
                  >
                    <KeyRound /> 加密保存 Token
                  </Button>
                  <Textarea
                    value={workerSource}
                    onChange={(event) => setWorkerSource(event.target.value)}
                    maxLength={262_144}
                    spellCheck={false}
                    disabled={!selectedWorker || !live}
                    className="min-h-44 border-white/8 bg-black/25 font-mono text-xs text-slate-300"
                  />
                  <Button
                    type="button"
                    onClick={() => void createWorkerVersion()}
                    disabled={!selectedWorker || !live || workerBusy}
                    className="w-full bg-cyan-300 text-slate-950 hover:bg-cyan-200"
                  >
                    <UploadCloud /> 保存预构建版本
                  </Button>
                </CardContent>
              </Card>

              <Card className="border-white/6 bg-[#101a2b]/88 ring-white/7">
                <CardHeader>
                  <CardTitle className="text-sm text-slate-100">
                    部署安全闸
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-500">
                    先生成版本化部署计划，再由操作者确认调用 Provider。
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <label className="block text-xs text-slate-400">
                    目标版本
                    <NativeSelect
                      value={deploymentVersionId}
                      onChange={(event) =>
                        setDeploymentVersionId(event.target.value)
                      }
                      disabled={!versions.length || deploymentPending}
                      className="mt-1.5 w-full [&_select]:border-white/8 [&_select]:bg-white/[0.035]"
                    >
                      {versions.map((version) => (
                        <NativeSelectOption key={version.id} value={version.id}>
                          {version.id}
                          {version.providerVersionId ? ' · 已上传' : ''}
                        </NativeSelectOption>
                      ))}
                    </NativeSelect>
                  </label>
                  <StatusRow
                    label="最新版本"
                    value={versions[0]?.id ?? '尚无版本'}
                    ready={versions.length > 0}
                  />
                  <StatusRow
                    label="最新计划"
                    value={deployments[0]?.state ?? '尚无部署计划'}
                    ready={deployments.length > 0}
                  />
                  <div className="grid grid-cols-2 gap-2 pt-2">
                    <Button
                      type="button"
                      onClick={() => void planDeployment('deploy')}
                      disabled={
                        !selectedVersion ||
                        !workerTokenMetadata ||
                        deploymentPending ||
                        workerBusy ||
                        !live
                      }
                      className="bg-cyan-300 text-slate-950 hover:bg-cyan-200"
                    >
                      生成发布计划
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => void planDeployment('rollback')}
                      disabled={
                        !selectedVersion?.providerVersionId ||
                        selectedWorker?.desiredVersionId ===
                          selectedVersion?.id ||
                        !workerTokenMetadata ||
                        deploymentPending ||
                        workerBusy ||
                        !live
                      }
                    >
                      生成回滚计划
                    </Button>
                  </div>
                  <AlertDialog>
                    <AlertDialogTrigger
                      render={
                        <Button
                          type="button"
                          disabled={
                            deployments[0]?.state !== 'ready_for_provider' ||
                            workerBusy ||
                            !live
                          }
                          className="w-full bg-amber-300 text-slate-950 hover:bg-amber-200"
                        />
                      }
                    >
                      <CloudCog /> 确认并执行最新计划
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>
                          执行 Cloudflare Worker{' '}
                          {deployments[0]?.kind === 'rollback'
                            ? '回滚'
                            : '发布'}
                          ？
                        </AlertDialogTitle>
                        <AlertDialogDescription>
                          将调用 Cloudflare Provider，把版本{' '}
                          {deployments[0]?.versionId ?? '—'} 应用到{' '}
                          {selectedWorker?.scriptName ?? '当前 Worker'}
                          。执行结果会记录在部署状态与审计日志中。
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>取消</AlertDialogCancel>
                        <AlertDialogAction
                          onClick={() => void executeDeployment()}
                        >
                          执行计划
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                  <p className="text-[11px] leading-5 text-slate-500">
                    Token 仅由控制面解封后交给 Provider
                    适配器；网页不会读取或回显 Token。
                    {deployments[0]?.providerState
                      ? ` Provider：${deployments[0].providerState}`
                      : ''}
                    {deployments[0]?.errorCode
                      ? ` 错误：${deployments[0].errorCode}`
                      : ''}
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </section>
  );
}

function StatusRow({
  label,
  value,
  ready,
}: {
  label: string;
  value: string;
  ready: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-white/6 bg-white/[0.025] px-3 py-2.5">
      <span className="text-xs text-slate-500">{label}</span>
      <span
        className={`max-w-[70%] truncate text-right font-mono text-[11px] ${
          ready ? 'text-emerald-300' : 'text-amber-200/70'
        }`}
      >
        {value}
      </span>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const severityClass =
    finding.severity === 'critical' || finding.severity === 'high'
      ? 'border-rose-300/15 bg-rose-300/[0.04] text-rose-200'
      : finding.severity === 'medium'
        ? 'border-amber-300/15 bg-amber-300/[0.04] text-amber-200'
        : 'border-cyan-300/15 bg-cyan-300/[0.04] text-cyan-200';
  return (
    <article className={`rounded-xl border p-4 ${severityClass}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium">{finding.title}</p>
          <p className="mt-1 font-mono text-[10px] opacity-55">
            {finding.ruleId}
          </p>
        </div>
        <Badge variant="outline" className="border-current/20 text-current">
          {finding.severity.toUpperCase()} ·{' '}
          {Math.round(finding.confidence * 100)}%
        </Badge>
      </div>
      <pre className="mt-3 overflow-auto rounded-lg bg-black/20 p-3 font-mono text-[10px] leading-5 text-slate-300">
        {JSON.stringify(finding.evidence, null, 2)}
      </pre>
      <p className="mt-3 text-[11px] leading-5 text-slate-500">
        误报提示：{finding.falsePositiveNote}
      </p>
    </article>
  );
}

async function apiError(response: Response, fallback: string) {
  try {
    const payload = (await response.json()) as {
      error?: { message?: string };
    };
    return payload.error?.message ?? fallback;
  } catch {
    return fallback;
  }
}

function formatTime(value?: string) {
  if (!value) return '—';
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return '—';
  return new Date(timestamp).toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function utf8Base64(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return window.btoa(binary);
}

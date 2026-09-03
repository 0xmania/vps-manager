'use client';

import {
  AlertTriangle,
  CheckCircle2,
  LoaderCircle,
  Play,
  RotateCw,
  Settings2,
} from 'lucide-react';
import { useState } from 'react';

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

type ActionId =
  | 'system_capabilities_v1'
  | 'package_update_check_v1'
  | 'service_status_v1'
  | 'service_restart_v1'
  | 'timezone_set_v1'
  | 'process_sigterm_v1'
  | 'host_reboot_plan_v1';

type Preview = {
  jobId: string;
  catalogVersion: string;
  scopeDigest: string;
  title: string;
  mutating: boolean;
  emergency: boolean;
  executionEnabled: boolean;
  retryPolicy: string;
  steps: Array<{
    id: string;
    phase: string;
    description: string;
    timeoutSeconds: number;
  }>;
};

type Execution = {
  jobState: string;
  status: string;
  stopped: boolean;
  idempotentReplay: boolean;
  steps: Array<{
    id: string;
    phase: string;
    state: string;
    stdout?: string;
    stderr?: string;
    exitCode: number;
    durationMillis: number;
    errorCode?: string;
  }>;
};

const actions: Array<{
  id: ActionId;
  label: string;
  mutating: boolean;
  emergency: boolean;
}> = [
  {
    id: 'system_capabilities_v1',
    label: '检查系统能力',
    mutating: false,
    emergency: false,
  },
  {
    id: 'package_update_check_v1',
    label: '检查可更新软件包',
    mutating: false,
    emergency: false,
  },
  {
    id: 'service_status_v1',
    label: '查看服务状态',
    mutating: false,
    emergency: false,
  },
  {
    id: 'service_restart_v1',
    label: '重启指定服务',
    mutating: true,
    emergency: true,
  },
  {
    id: 'timezone_set_v1',
    label: '设置时区',
    mutating: true,
    emergency: false,
  },
  {
    id: 'process_sigterm_v1',
    label: '终止指定进程（SIGTERM）',
    mutating: true,
    emergency: true,
  },
  {
    id: 'host_reboot_plan_v1',
    label: '计划主机重启',
    mutating: true,
    emergency: true,
  },
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function apiError(response: Response, fallback: string) {
  try {
    const payload: unknown = await response.json();
    if (
      isRecord(payload) &&
      isRecord(payload.error) &&
      typeof payload.error.message === 'string'
    ) {
      return payload.error.message;
    }
  } catch {
    // Use the bounded local fallback.
  }
  return fallback;
}

const demoPreview: Preview = {
  jobId: 'job_demo',
  catalogVersion: '2026-08-29.1',
  scopeDigest: 'demo-only',
  title: '检查系统能力',
  mutating: false,
  emergency: false,
  executionEnabled: false,
  retryPolicy: 'never',
  steps: [
    {
      id: 'preflight',
      phase: 'preflight',
      description: '核对系统与工具可用性',
      timeoutSeconds: 10,
    },
    {
      id: 'evidence',
      phase: 'evidence',
      description: '采集变更前只读证据',
      timeoutSeconds: 10,
    },
    {
      id: 'apply',
      phase: 'apply',
      description: '执行服务器固定动作',
      timeoutSeconds: 20,
    },
    {
      id: 'verify',
      phase: 'verify',
      description: '验证最终状态',
      timeoutSeconds: 10,
    },
  ],
};

export function RunbookWorkspace({
  hostId,
  hostName,
  enabled,
  live,
}: {
  hostId: string;
  hostName: string;
  enabled: boolean;
  live: boolean;
}) {
  const [actionId, setActionId] = useState<ActionId>('system_capabilities_v1');
  const [service, setService] = useState('nginx');
  const [timezone, setTimezone] = useState('UTC');
  const [pid, setPid] = useState('');
  const [processStartTicks, setProcessStartTicks] = useState('');
  const [reason, setReason] = useState('常规配置与故障处理');
  const [incidentId, setIncidentId] = useState('');
  const [preview, setPreview] = useState<Preview | null>(
    live ? null : demoPreview,
  );
  const [execution, setExecution] = useState<Execution | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');

  function parameters() {
    if (actionId === 'service_status_v1' || actionId === 'service_restart_v1') {
      return { service };
    }
    if (actionId === 'timezone_set_v1') return { timezone };
    if (actionId === 'process_sigterm_v1') {
      return {
        pid: Number(pid),
        processStartTicks: Number(processStartTicks),
      };
    }
    return {};
  }

  function changeAction(value: string) {
    if (!actions.some((item) => item.id === value)) return;
    setActionId(value as ActionId);
    setPreview(null);
    setExecution(null);
    setNotice('');
  }

  async function requestPreview() {
    if (!enabled || !live) return;
    setBusy(true);
    setPreview(null);
    setExecution(null);
    setNotice('');
    try {
      const response = await fetch(
        `/api/control-plane/hosts/${encodeURIComponent(hostId)}/runbooks/preview`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            actionId,
            version: 1,
            parameters: parameters(),
          }),
        },
      );
      if (!response.ok) {
        throw new Error(await apiError(response, '无法生成操作预览'));
      }
      const job: unknown = await response.json();
      if (
        !isRecord(job) ||
        typeof job.id !== 'string' ||
        !isRecord(job.runbookPreview)
      ) {
        throw new Error('控制面返回了无效的操作预览');
      }
      setPreview({
        ...(job.runbookPreview as Omit<Preview, 'jobId'>),
        jobId: job.id,
      });
      setNotice('预览已生成，请核对步骤和影响后再执行。');
    } catch (error) {
      setNotice(error instanceof Error ? error.message : '生成预览失败');
    } finally {
      setBusy(false);
    }
  }

  async function execute() {
    if (!preview || !enabled || !live) return;
    if (reason.trim().length < 8 || reason.trim().length > 500) {
      setNotice('请输入 8–500 个字符的操作理由');
      return;
    }
    if (
      preview.emergency &&
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/u.test(incidentId.trim())
    ) {
      setNotice('事故编号须以字母或数字开头，可包含 . _ : -');
      return;
    }
    setBusy(true);
    setExecution(null);
    setNotice('');
    try {
      const response = await fetch(
        `/api/control-plane/jobs/${encodeURIComponent(preview.jobId)}/runbook-execute`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            scopeDigest: preview.scopeDigest,
            reason: reason.trim(),
            incidentId: preview.emergency ? incidentId.trim() : undefined,
          }),
        },
      );
      if (!response.ok) {
        throw new Error(await apiError(response, '执行操作失败'));
      }
      const job: unknown = await response.json();
      if (!isRecord(job) || !isRecord(job.runbookExecution)) {
        throw new Error('控制面返回了无效的操作结果');
      }
      const jobState = typeof job.state === 'string' ? job.state : 'unknown';
      const result = {
        ...(job.runbookExecution as Omit<Execution, 'jobState'>),
        jobState,
      };
      setExecution(result);
      setNotice(
        jobState === 'succeeded' && result.status === 'succeeded'
          ? '操作已完成，逐步结果已写入审计。'
          : `操作未完成（${result.status}），请核对失败步骤与审计记录。`,
      );
    } catch (error) {
      setNotice(error instanceof Error ? error.message : '执行操作失败');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[340px_minmax(0,1fr)]">
      <Card className="border-white/6 bg-[#101a2b]/88 ring-white/7">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm text-slate-100">
            <Settings2 className="size-4 text-cyan-300" />
            简单配置与应急操作
          </CardTitle>
          <CardDescription className="text-xs text-slate-500">
            {hostName} · 固定 Recipe，不接受自由 Shell
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <label className="block text-xs text-slate-400">
            操作
            <NativeSelect
              value={actionId}
              onChange={(event) => changeAction(event.target.value)}
              className="mt-1.5 w-full [&_select]:border-white/8 [&_select]:bg-white/[0.035]"
            >
              {actions.map((item) => (
                <NativeSelectOption key={item.id} value={item.id}>
                  {item.label}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </label>
          {actionId === 'service_status_v1' ||
          actionId === 'service_restart_v1' ? (
            <label className="block text-xs text-slate-400">
              服务
              <NativeSelect
                value={service}
                onChange={(event) => {
                  setService(event.target.value);
                  setPreview(null);
                }}
                className="mt-1.5 w-full [&_select]:border-white/8 [&_select]:bg-white/[0.035]"
              >
                {['nginx', 'ssh', 'docker', 'cron'].map((value) => (
                  <NativeSelectOption key={value} value={value}>
                    {value}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            </label>
          ) : null}
          {actionId === 'timezone_set_v1' ? (
            <label className="block text-xs text-slate-400">
              时区
              <NativeSelect
                value={timezone}
                onChange={(event) => {
                  setTimezone(event.target.value);
                  setPreview(null);
                }}
                className="mt-1.5 w-full [&_select]:border-white/8 [&_select]:bg-white/[0.035]"
              >
                {[
                  'UTC',
                  'Asia/Shanghai',
                  'America/New_York',
                  'Europe/London',
                ].map((value) => (
                  <NativeSelectOption key={value} value={value}>
                    {value}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            </label>
          ) : null}
          {actionId === 'process_sigterm_v1' ? (
            <div className="grid grid-cols-2 gap-2">
              <Input
                inputMode="numeric"
                value={pid}
                onChange={(event) => {
                  setPid(event.target.value.replace(/\D/gu, '').slice(0, 10));
                  setPreview(null);
                }}
                placeholder="PID ≥ 100"
              />
              <Input
                inputMode="numeric"
                value={processStartTicks}
                onChange={(event) => {
                  setProcessStartTicks(
                    event.target.value.replace(/\D/gu, '').slice(0, 20),
                  );
                  setPreview(null);
                }}
                placeholder="start ticks"
              />
            </div>
          ) : null}
          <Button
            type="button"
            variant="outline"
            onClick={() => void requestPreview()}
            disabled={!enabled || !live || busy}
            className="w-full border-cyan-300/15 text-cyan-200"
          >
            {busy ? <LoaderCircle className="animate-spin" /> : <RotateCw />}
            生成执行预览
          </Button>
          {!enabled ? (
            <p className="text-[11px] leading-5 text-amber-200/60">
              需要固定主机指纹并配置 SSH 凭据。
            </p>
          ) : null}
          {notice ? (
            <output className="block text-[11px] leading-5 text-cyan-100/65">
              {notice}
            </output>
          ) : null}
        </CardContent>
      </Card>

      <Card className="border-white/6 bg-[#101a2b]/88 ring-white/7">
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm text-slate-100">
            {preview?.title ?? '执行预览'}
            {preview?.mutating ? (
              <Badge
                variant="outline"
                className="border-amber-300/20 text-amber-300"
              >
                会修改主机
              </Badge>
            ) : (
              <Badge variant="outline">只读</Badge>
            )}
          </CardTitle>
          <CardDescription className="text-xs text-slate-500">
            {preview
              ? `Catalog ${preview.catalogVersion} · retry ${preview.retryPolicy}`
              : '先生成预览；执行时会按顺序预检、取证、应用和验证。'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {preview ? (
            <>
              <div className="grid gap-2 sm:grid-cols-2">
                {preview.steps.map((step, index) => (
                  <div
                    key={step.id}
                    className="rounded-lg border border-white/6 bg-black/15 p-3"
                  >
                    <p className="font-mono text-[10px] text-cyan-300/70">
                      {index + 1}. {step.phase} · {step.timeoutSeconds}s
                    </p>
                    <p className="mt-1 text-[11px] leading-5 text-slate-500">
                      {step.description}
                    </p>
                  </div>
                ))}
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                <Input
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  minLength={8}
                  maxLength={500}
                  placeholder="操作理由"
                  disabled={!live}
                />
                {preview.emergency ? (
                  <Input
                    value={incidentId}
                    onChange={(event) => setIncidentId(event.target.value)}
                    maxLength={128}
                    placeholder="事故编号"
                    disabled={!live}
                  />
                ) : null}
              </div>
              {preview.mutating ? (
                <AlertDialog>
                  <AlertDialogTrigger
                    render={
                      <Button
                        variant="destructive"
                        disabled={!live || !preview.executionEnabled || busy}
                        className="w-full"
                      />
                    }
                  >
                    <AlertTriangle /> 核对后执行变更
                  </AlertDialogTrigger>
                  <AlertDialogContent className="border-white/8 bg-[#111d2f] text-slate-100">
                    <AlertDialogHeader>
                      <AlertDialogTitle>
                        确认执行：{preview.title}？
                      </AlertDialogTitle>
                      <AlertDialogDescription>
                        目标为 {hostName}
                        。任务失败后不会自动重试，请确认事故编号、参数和预览步骤。
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>取消</AlertDialogCancel>
                      <AlertDialogAction
                        variant="destructive"
                        onClick={() => void execute()}
                      >
                        确认执行
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              ) : (
                <Button
                  type="button"
                  onClick={() => void execute()}
                  disabled={!live || !preview.executionEnabled || busy}
                  className="w-full bg-cyan-300 text-slate-950 hover:bg-cyan-200"
                >
                  <Play /> 执行只读 Recipe
                </Button>
              )}
              {!preview.executionEnabled ? (
                <p className="text-[11px] text-amber-200/60">
                  当前 Connector 未开启此类执行；预览仍可用于核对。
                </p>
              ) : null}
            </>
          ) : null}
          {execution ? (
            <div className="border-t border-white/6 pt-4">
              <div className="mb-3 flex items-center gap-2 text-xs text-slate-400">
                {execution.jobState === 'succeeded' &&
                execution.status === 'succeeded' ? (
                  <CheckCircle2 className="size-4 text-emerald-300" />
                ) : (
                  <AlertTriangle className="size-4 text-rose-300" />
                )}
                {execution.jobState === 'succeeded' &&
                execution.status === 'succeeded'
                  ? '操作成功'
                  : '操作未完成'}{' '}
                · {execution.status}
                {execution.idempotentReplay ? ' · 幂等结果回放' : ''}
              </div>
              <div className="space-y-2">
                {execution.steps.map((step) => (
                  <div
                    key={step.id}
                    className="rounded-lg border border-white/6 p-3"
                  >
                    <p className="text-[11px] text-slate-400">
                      {step.phase} · {step.state} · exit {step.exitCode} ·{' '}
                      {step.durationMillis}ms
                    </p>
                    {step.stdout ? (
                      <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[10px] text-emerald-200/70">
                        {step.stdout}
                      </pre>
                    ) : null}
                    {step.stderr ? (
                      <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[10px] text-rose-200/70">
                        {step.stderr}
                      </pre>
                    ) : null}
                    {step.errorCode ? (
                      <p className="mt-2 font-mono text-[10px] text-rose-300/70">
                        error: {step.errorCode}
                      </p>
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}

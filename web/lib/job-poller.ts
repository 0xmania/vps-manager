export type ControlPlaneJobState =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'timed_out'
  | 'cancelled';

export type PollableControlPlaneJob = {
  id: string;
  state: ControlPlaneJobState;
};

const pendingStates = new Set<ControlPlaneJobState>(['queued', 'running']);

async function responseError(response: Response) {
  const fallback = `无法读取任务状态（${response.status}）`;
  try {
    const payload = (await response.json()) as {
      error?: { message?: unknown };
    };
    if (typeof payload.error?.message === 'string') {
      return payload.error.message;
    }
  } catch {
    return fallback;
  }
  return fallback;
}

export async function pollControlPlaneJob<T extends PollableControlPlaneJob>(
  jobId: string,
  options: { signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<T> {
  const deadline = Date.now() + (options.timeoutMs ?? 105_000);

  while (Date.now() < deadline) {
    await new Promise((resolve) => window.setTimeout(resolve, 750));
    options.signal?.throwIfAborted();

    const response = await fetch(
      `/api/control-plane/jobs/${encodeURIComponent(jobId)}`,
      { cache: 'no-store', signal: options.signal },
    );
    if (!response.ok) throw new Error(await responseError(response));

    const job = (await response.json()) as T;
    if (!pendingStates.has(job.state)) return job;
  }

  throw new Error(`任务 ${jobId} 轮询超时，请到任务中心核对最终状态`);
}

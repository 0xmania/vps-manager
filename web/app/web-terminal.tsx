'use client';

import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { LoaderCircle, PlugZap, SquareTerminal, Unplug } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

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

type TerminalBinding = {
  principalId: string;
  sessionId: string;
  roles: string[];
  hostId: string;
  credentialId: string;
  action: 'web_ssh_v1';
};

type TerminalTicket = {
  protocolVersion: 'v1';
  ticket: string;
  connectionId: string;
  expiresAt: string;
  webSocketUrl: string;
  protocol: 'vpsmgr.webssh.v1';
  binding: TerminalBinding;
};

const maxServerMessageBytes = 128 << 10;
const maxOutputChunkBytes = 64 << 10;
const maxInputChunkBytes = 8 << 10;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function safeWebSocketUrl(value: string): URL | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (
    (url.protocol !== 'wss:' && !(url.protocol === 'ws:' && local)) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    return null;
  }
  return url;
}

function parseTicket(value: unknown, hostId: string): TerminalTicket | null {
  if (!isRecord(value) || !isRecord(value.binding)) return null;
  const ticket = value.ticket;
  const protocolVersion = value.protocolVersion;
  const connectionId = value.connectionId;
  const expiresAt = value.expiresAt;
  const webSocketUrl = value.webSocketUrl;
  const protocol = value.protocol;
  const binding = value.binding;
  if (
    typeof ticket !== 'string' ||
    ticket.length < 32 ||
    ticket.length > 256 ||
    protocolVersion !== 'v1' ||
    typeof connectionId !== 'string' ||
    connectionId.length < 8 ||
    connectionId.length > 128 ||
    typeof expiresAt !== 'string' ||
    !Number.isFinite(Date.parse(expiresAt)) ||
    Date.parse(expiresAt) <= Date.now() ||
    typeof webSocketUrl !== 'string' ||
    !safeWebSocketUrl(webSocketUrl) ||
    protocol !== 'vpsmgr.webssh.v1' ||
    binding.action !== 'web_ssh_v1' ||
    binding.hostId !== hostId ||
    typeof binding.principalId !== 'string' ||
    binding.principalId.length < 1 ||
    binding.principalId.length > 128 ||
    typeof binding.sessionId !== 'string' ||
    binding.sessionId.length < 1 ||
    binding.sessionId.length > 128 ||
    !Array.isArray(binding.roles) ||
    binding.roles.length < 1 ||
    binding.roles.length > 16 ||
    !binding.roles.every(
      (role) =>
        typeof role === 'string' && role.length >= 1 && role.length <= 64,
    ) ||
    typeof binding.credentialId !== 'string' ||
    binding.credentialId.length < 1 ||
    binding.credentialId.length > 128
  ) {
    return null;
  }
  return value as TerminalTicket;
}

function decodeBase64(value: string): Uint8Array | null {
  if (
    value.length > Math.ceil((maxOutputChunkBytes * 4) / 3) + 4 ||
    !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)
  ) {
    return null;
  }
  try {
    const binary = atob(value);
    if (binary.length > maxOutputChunkBytes) return null;
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function encodeBase64(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function responseError(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as {
      error?: { message?: unknown };
    };
    if (typeof body.error?.message === 'string') return body.error.message;
  } catch {
    // A bounded generic message is safer than reflecting an arbitrary body.
  }
  return `终端请求失败（${response.status}）`;
}

export function WebTerminal({
  hostId,
  hostName,
  enabled,
}: {
  hostId: string;
  hostName: string;
  enabled: boolean;
}) {
  const container = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const socket = useRef<WebSocket | null>(null);
  const inputSubscription = useRef<{ dispose(): void } | null>(null);
  const resizeSubscription = useRef<{ dispose(): void } | null>(null);
  const resizeObserver = useRef<ResizeObserver | null>(null);
  const ticketRequest = useRef<AbortController | null>(null);
  const [reason, setReason] = useState('交互式故障排查');
  const [state, setState] = useState<
    'idle' | 'requesting' | 'connecting' | 'connected' | 'closed'
  >('idle');
  const [error, setError] = useState('');

  useEffect(() => {
    return () => {
      ticketRequest.current?.abort();
      ticketRequest.current = null;
      socket.current?.close(1000, 'terminal component unmounted');
      inputSubscription.current?.dispose();
      resizeSubscription.current?.dispose();
      resizeObserver.current?.disconnect();
      terminal.current?.dispose();
      socket.current = null;
      inputSubscription.current = null;
      resizeSubscription.current = null;
      resizeObserver.current = null;
      terminal.current = null;
      fit.current = null;
    };
  }, []);

  function ensureTerminal() {
    if (terminal.current || !container.current) return;
    const instance = new Terminal({
      cursorBlink: true,
      convertEol: true,
      scrollback: 2000,
      fontSize: 13,
      fontFamily:
        'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
      minimumContrastRatio: 4.5,
      logLevel: 'off',
      linkHandler: { activate: () => {}, allowNonHttpProtocols: false },
      theme: {
        background: '#07101d',
        foreground: '#cbd5e1',
        cursor: '#67e8f9',
        selectionBackground: '#164e63',
      },
    });
    const fitAddon = new FitAddon();
    instance.loadAddon(fitAddon);
    instance.open(container.current);
    fitAddon.fit();
    instance.writeln('\x1b[36mVPS Manager Web SSH\x1b[0m');
    instance.writeln('等待一次性连接票据…');
    terminal.current = instance;
    fit.current = fitAddon;
  }

  async function connect() {
    if (!enabled || state === 'requesting' || state === 'connecting') return;
    const normalizedReason = reason.trim();
    if (normalizedReason.length < 8 || normalizedReason.length > 500) {
      setError('请输入 8–500 个字符的连接理由');
      return;
    }
    setError('');
    setState('requesting');
    ensureTerminal();
    const instance = terminal.current;
    const fitAddon = fit.current;
    if (!instance || !fitAddon) {
      setState('closed');
      setError('终端初始化失败');
      return;
    }
    fitAddon.fit();
    const controller = new AbortController();
    ticketRequest.current?.abort();
    ticketRequest.current = controller;
    try {
      const response = await fetch(
        `/api/control-plane/hosts/${encodeURIComponent(hostId)}/terminal-sessions`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          signal: controller.signal,
          body: JSON.stringify({
            reason: normalizedReason,
            columns: instance.cols,
            rows: instance.rows,
          }),
        },
      );
      if (!response.ok) throw new Error(await responseError(response));
      const rawTicket: unknown = await response.json();
      const connectionTicket = parseTicket(rawTicket, hostId);
      if (!connectionTicket) throw new Error('控制面返回了无效的终端票据');
      const url = safeWebSocketUrl(connectionTicket.webSocketUrl);
      if (!url) throw new Error('控制面返回了不安全的终端地址');
      if (controller.signal.aborted) return;

      setState('connecting');
      const webSocket = new WebSocket(url, connectionTicket.protocol);
      socket.current = webSocket;
      webSocket.addEventListener('open', () => {
        webSocket.send(
          JSON.stringify({
            type: 'hello',
            ticket: connectionTicket.ticket,
            connectionId: connectionTicket.connectionId,
            binding: connectionTicket.binding,
          }),
        );
      });
      webSocket.addEventListener('message', (event) => {
        if (
          typeof event.data !== 'string' ||
          event.data.length > maxServerMessageBytes
        ) {
          webSocket.close(1009, 'server message limit');
          setError('终端服务返回了过大的消息');
          return;
        }
        let message: unknown;
        try {
          message = JSON.parse(event.data);
        } catch {
          webSocket.close(1007, 'invalid terminal message');
          return;
        }
        if (!isRecord(message) || typeof message.type !== 'string') {
          webSocket.close(1007, 'invalid terminal message');
          return;
        }
        if (message.type === 'ready') {
          if (message.sessionId !== connectionTicket.connectionId) {
            webSocket.close(1008, 'session binding mismatch');
            return;
          }
          instance.clear();
          instance.focus();
          setState('connected');
          return;
        }
        if (message.type === 'output' && typeof message.data === 'string') {
          const output = decodeBase64(message.data);
          if (!output) {
            webSocket.close(1007, 'invalid terminal output');
            return;
          }
          instance.write(output);
          return;
        }
        if (
          message.type === 'exit' &&
          typeof message.exitCode === 'number' &&
          typeof message.reason === 'string'
        ) {
          instance.writeln(
            `\r\n\x1b[33m[session ended: ${message.exitCode}]\x1b[0m`,
          );
          setState('closed');
          return;
        }
        if (message.type === 'error' && typeof message.message === 'string') {
          setError(message.message.slice(0, 300));
          setState('closed');
          return;
        }
        webSocket.close(1007, 'unsupported terminal message');
      });
      webSocket.addEventListener('error', () => {
        setError('WebSocket 终端连接失败');
        setState('closed');
      });
      webSocket.addEventListener('close', () => {
        if (socket.current === webSocket) {
          socket.current = null;
          inputSubscription.current?.dispose();
          resizeSubscription.current?.dispose();
          resizeObserver.current?.disconnect();
          inputSubscription.current = null;
          resizeSubscription.current = null;
          resizeObserver.current = null;
          setState((current) => (current === 'idle' ? current : 'closed'));
        }
      });

      inputSubscription.current?.dispose();
      inputSubscription.current = instance.onData((data) => {
        if (webSocket.readyState !== WebSocket.OPEN) return;
        const bytes = new TextEncoder().encode(data);
        for (
          let offset = 0;
          offset < bytes.length;
          offset += maxInputChunkBytes
        ) {
          webSocket.send(
            JSON.stringify({
              type: 'input',
              data: encodeBase64(
                bytes.subarray(offset, offset + maxInputChunkBytes),
              ),
            }),
          );
        }
      });
      resizeSubscription.current?.dispose();
      resizeSubscription.current = instance.onResize((size) => {
        if (webSocket.readyState !== WebSocket.OPEN) return;
        webSocket.send(
          JSON.stringify({
            type: 'resize',
            size: { columns: size.cols, rows: size.rows },
          }),
        );
      });
      resizeObserver.current?.disconnect();
      resizeObserver.current = new ResizeObserver(() => fitAddon.fit());
      if (container.current) resizeObserver.current.observe(container.current);
    } catch (caught) {
      if (controller.signal.aborted) return;
      setState('closed');
      setError(caught instanceof Error ? caught.message : '无法创建终端会话');
    } finally {
      if (ticketRequest.current === controller) {
        ticketRequest.current = null;
      }
    }
  }

  function disconnect() {
    ticketRequest.current?.abort();
    socket.current?.close(1000, 'user disconnected');
    socket.current = null;
    setState('closed');
  }

  const busy = state === 'requesting' || state === 'connecting';
  return (
    <div className="grid gap-4 xl:grid-cols-[320px_minmax(0,1fr)]">
      <Card className="border-white/6 bg-[#101a2b]/88 ring-white/7">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm text-slate-100">
            <SquareTerminal className="size-4 text-cyan-300" />
            Web SSH
          </CardTitle>
          <CardDescription className="text-xs text-slate-500">
            {hostName} · 一次性票据 · 默认关闭全部转发和文件传输
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <label
            htmlFor="terminal-reason"
            className="block text-xs text-slate-400"
          >
            连接理由
            <Input
              id="terminal-reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              minLength={8}
              maxLength={500}
              disabled={state === 'connected'}
              className="mt-1.5 border-white/8 bg-black/20"
            />
          </label>
          <div className="flex items-center gap-2">
            <Badge
              variant="outline"
              className={
                state === 'connected'
                  ? 'border-emerald-300/20 text-emerald-300'
                  : 'border-white/10 text-slate-500'
              }
            >
              {state.toUpperCase()}
            </Badge>
            <span className="text-[10px] text-slate-600">最长 1 小时</span>
          </div>
          {state === 'connected' ? (
            <Button
              type="button"
              variant="destructive"
              onClick={disconnect}
              className="w-full"
            >
              <Unplug /> 断开终端
            </Button>
          ) : (
            <Button
              type="button"
              onClick={() => void connect()}
              disabled={!enabled || busy}
              className="w-full bg-cyan-300 text-slate-950 hover:bg-cyan-200"
            >
              {busy ? <LoaderCircle className="animate-spin" /> : <PlugZap />}
              创建终端会话
            </Button>
          )}
          {!enabled ? (
            <p className="text-[11px] leading-5 text-amber-200/60">
              需要连接控制面、固定主机指纹并配置 SSH 凭据。
            </p>
          ) : null}
          {error ? (
            <output className="block text-[11px] leading-5 text-rose-300/80">
              {error}
            </output>
          ) : null}
        </CardContent>
      </Card>
      <Card className="overflow-hidden border-white/6 bg-[#07101d] ring-white/7">
        <CardContent className="p-0">
          <div
            ref={container}
            aria-label={`${hostName} 的安全终端`}
            className="h-[430px] w-full p-3 [&_.xterm]:h-full"
          />
        </CardContent>
      </Card>
    </div>
  );
}

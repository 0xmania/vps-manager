import {
  ArrowRight,
  Fingerprint,
  LockKeyhole,
  Server,
  ShieldCheck,
} from 'lucide-react';
import { redirect } from 'next/navigation';

import { Badge } from '@/components/ui/badge';

import { chatGPTSignInPath, getChatGPTUser } from '../chatgpt-auth';

export const dynamic = 'force-dynamic';

export default async function LoginPage() {
  const user = await getChatGPTUser();
  if (user) redirect('/');

  return (
    <main className="relative grid min-h-screen place-items-center overflow-hidden bg-[#09111e] px-5 py-10 text-slate-100">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_15%_20%,rgba(34,211,238,.10),transparent_24rem),radial-gradient(circle_at_85%_80%,rgba(52,211,153,.07),transparent_26rem)]" />
      <div className="pointer-events-none absolute inset-0 opacity-20 [background-image:linear-gradient(rgba(148,163,184,.08)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,.08)_1px,transparent_1px)] [background-size:48px_48px]" />

      <section className="relative w-full max-w-[1040px] overflow-hidden rounded-[24px] border border-white/8 bg-[#0d1727]/92 shadow-[0_30px_100px_rgba(0,0,0,.45)] backdrop-blur-xl lg:grid lg:grid-cols-[1.15fr_.85fr]">
        <div className="border-b border-white/7 p-7 sm:p-10 lg:border-b-0 lg:border-r lg:p-12">
          <div className="flex items-center gap-3">
            <div className="grid size-10 place-items-center rounded-xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-300">
              <Server className="size-4.5" />
            </div>
            <div>
              <p className="text-sm font-semibold">VPS Manager</p>
              <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-600">
                secure operations plane
              </p>
            </div>
          </div>

          <div className="mt-14 max-w-xl">
            <Badge
              variant="outline"
              className="border-cyan-300/20 bg-cyan-300/8 font-mono text-[10px] text-cyan-300"
            >
              ACCESS CONTROLLED
            </Badge>
            <h1 className="mt-5 text-3xl font-semibold tracking-[-0.045em] text-white sm:text-[42px] sm:leading-[1.08]">
              安全进入你的
              <br />
              基础设施控制面
            </h1>
            <p className="mt-5 max-w-lg text-sm leading-7 text-slate-500">
              统一管理 VPS 运行快照、受控命令、SSH
              主机身份、异常扫描与部署任务。所有高风险操作均经过服务端授权与审计。
            </p>
          </div>

          <div className="mt-12 grid gap-3 sm:grid-cols-3">
            {[
              { icon: Fingerprint, label: '主机指纹固定' },
              { icon: LockKeyhole, label: '凭据隔离使用' },
              { icon: ShieldCheck, label: '操作全程审计' },
            ].map(({ icon: Icon, label }) => (
              <div
                key={label}
                className="flex items-center gap-2 rounded-xl border border-white/6 bg-white/[0.025] px-3 py-3 text-[11px] text-slate-400"
              >
                <Icon className="size-3.5 text-cyan-300/80" />
                {label}
              </div>
            ))}
          </div>
        </div>

        <div className="flex flex-col justify-center p-7 sm:p-10 lg:p-12">
          <p className="text-xs font-semibold uppercase tracking-[0.13em] text-slate-600">
            身份认证
          </p>
          <h2 className="mt-3 text-xl font-semibold tracking-tight text-slate-100">
            登录运维工作台
          </h2>
          <p className="mt-2 text-sm leading-6 text-slate-500">
            使用平台托管身份登录，控制面在服务端映射角色与可管理的主机范围。
          </p>

          <a
            href={chatGPTSignInPath('/')}
            target="_top"
            className="mt-8 flex h-11 items-center justify-center gap-2 rounded-xl bg-cyan-300 px-4 text-sm font-semibold text-slate-950 transition-colors hover:bg-cyan-200 focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-cyan-300/35"
          >
            继续安全登录
            <ArrowRight className="size-4" />
          </a>

          <div className="mt-5 rounded-xl border border-amber-300/12 bg-amber-300/[0.045] p-4">
            <p className="text-[11px] leading-5 text-amber-100/60">
              终端、凭据和生产部署等敏感操作还会经过独立确认与审计。
            </p>
          </div>

          <p className="mt-8 text-center text-[10px] leading-5 text-slate-700">
            登录即表示你的会话将受到超时、权限和审计策略约束。
          </p>
        </div>
      </section>
    </main>
  );
}

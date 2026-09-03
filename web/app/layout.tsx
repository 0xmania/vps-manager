import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

export const metadata: Metadata = {
  metadataBase: new URL(
    process.env.NEXT_PUBLIC_SITE_ORIGIN ?? 'http://localhost:3000',
  ),
  title: 'VPS Manager · 自托管运维面板',
  description:
    '用于管理 VPS、运行快照、受控 SSH、异常扫描和 Cloudflare Workers 部署的自托管运维面板。',
  openGraph: {
    title: 'VPS Manager',
    description: '自托管 Linux VPS 运维面板',
    type: 'website',
    images: [
      {
        url: '/og.png',
        width: 1672,
        height: 941,
        alt: 'VPS Manager · 自托管运维面板',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'VPS Manager',
    description: '自托管 Linux VPS 运维面板',
    images: ['/og.png'],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="zh-CN" className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}

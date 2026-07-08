import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SSL CSR Decoder & Analyzer",
  description:
    "SSL証明書署名要求 (CSR) の内容を安全にブラウザ上でパースし、詳細情報を可視化するツールです。",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ja">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&family=Outfit:wght@300;400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}

# CSR Decoder

SSL/TLS 証明書署名要求 (CSR) をブラウザ上で安全にデコード・解析するWebアプリケーションです。

**https://csr-checker.lolipop-now.app**

## 機能

- CSR (PEM形式) のパースと可視化
- 署名の整合性検証
- 申請者情報 (Subject) の表示 — CN, O, OU, C, ST, L 等
- 拡張情報 (Extensions) の表示 — SANs (Subject Alternative Names) 等
- 公開鍵の詳細表示 (アルゴリズム, 鍵長, PEM)
- すべての処理がクライアントサイドで完結（サーバーへのデータ送信なし）

## 技術スタック

- [Next.js](https://nextjs.org/) 15 (App Router)
- TypeScript
- [node-forge](https://github.com/digitalbazaar/forge) — CSRパース・署名検証

## ローカル開発

```bash
npm install
npm run dev
```

http://localhost:3000 で起動します。

## デプロイ

[ロリポップ！デプロイナウ](https://deploy.lolipop.jp/) を使用しています。

```bash
npm install -g lolipop
lolipop deploy
```

"use client";

import type { CsrResult } from "@/lib/csr-parser";

export default function ResultDisplay({ result }: { result: CsrResult }) {
  const {
    signatureValid,
    algorithm,
    keySize,
    subject,
    extensions,
    publicKeyPem,
  } = result;

  return (
    <section className="card result-card">
      <div className="card-header border-bottom">
        <h2>解析結果</h2>
        <span
          className={`badge ${signatureValid ? "badge-valid" : "badge-invalid"}`}
        >
          {signatureValid ? "署名検証: 有効" : "署名検証: 無効"}
        </span>
      </div>

      {/* Status Grid */}
      <div className="status-grid">
        <div className="status-item">
          <span className="status-label">署名の整合性</span>
          <span
            className={`status-value ${signatureValid ? "color-success" : "color-danger"}`}
          >
            {signatureValid ? "検証成功 (改ざんなし)" : "検証失敗 (不整合)"}
          </span>
        </div>
        <div className="status-item">
          <span className="status-label">鍵アルゴリズム</span>
          <span className="status-value">{algorithm}</span>
        </div>
        <div className="status-item">
          <span className="status-label">公開鍵サイズ</span>
          <span className="status-value">{keySize}</span>
        </div>
      </div>

      {/* Subject Table */}
      <div className="result-section">
        <h3>申請者情報 (Subject)</h3>
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>属性 (OID)</th>
                <th>値</th>
                <th>説明</th>
              </tr>
            </thead>
            <tbody>
              {subject.length === 0 ? (
                <tr>
                  <td colSpan={3} style={{ textAlign: "center" }}>
                    属性情報がありません
                  </td>
                </tr>
              ) : (
                subject.map((attr, i) => (
                  <tr key={i}>
                    <td>
                      <strong>{attr.name}</strong>
                      {attr.oid && (
                        <span className="oid-tag">OID: {attr.oid}</span>
                      )}
                    </td>
                    <td
                      style={{
                        fontFamily: "monospace",
                        wordBreak: "break-all",
                      }}
                    >
                      {attr.value}
                    </td>
                    <td
                      style={{
                        fontSize: "0.85rem",
                        color: "var(--text-muted)",
                      }}
                    >
                      {attr.description}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Extensions */}
      {extensions.length > 0 && (
        <div className="result-section">
          <h3>拡張情報 (Extensions)</h3>
          <div className="extensions-list">
            {extensions.map((ext, i) => (
              <div key={i} className="extension-item">
                <div className="extension-name">{ext.name}</div>
                <div className="extension-value">
                  {ext.altNames
                    ? ext.altNames
                        .map((an) => `${an.typeLabel}: ${an.value}`)
                        .join("\n")
                    : ext.rawValue || "値が空です"}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Public Key PEM */}
      <div className="result-section">
        <details className="collapsible-details">
          <summary>公開鍵の技術詳細 (PEM / Modulus)</summary>
          <div className="details-content">
            <pre>
              <code className="code-block">{publicKeyPem}</code>
            </pre>
          </div>
        </details>
      </div>
    </section>
  );
}

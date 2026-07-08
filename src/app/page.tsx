"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { type CsrResult, DEMO_CSR_PEM, parseCSR } from "@/lib/csr-parser";
import ErrorAlert from "@/components/ErrorAlert";
import ResultDisplay from "@/components/ResultDisplay";

export default function Home() {
  const [csrInput, setCsrInput] = useState("");
  const [result, setResult] = useState<CsrResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  const handleAnalyze = useCallback(() => {
    setError(null);
    setResult(null);

    const pem = csrInput.trim();
    if (!pem) {
      setError("CSRデータをテキストエリアに入力してください。");
      return;
    }

    if (
      !pem.includes("-----BEGIN CERTIFICATE REQUEST-----") ||
      !pem.includes("-----END CERTIFICATE REQUEST-----")
    ) {
      setError(
        '無効なフォーマットです。CSRは "-----BEGIN CERTIFICATE REQUEST-----" で始まり "-----END CERTIFICATE REQUEST-----" で終わる必要があります。'
      );
      return;
    }

    try {
      const parsed = parseCSR(pem);
      setResult(parsed);
    } catch (e) {
      const msg =
        e instanceof Error ? e.message : "不明なエラーが発生しました。";
      setError(
        `CSRの解析に失敗しました。データが破損しているか、非対応の暗号方式の可能性があります。\n詳細: ${msg}`
      );
    }
  }, [csrInput]);

  const handleLoadDemo = useCallback(() => {
    setCsrInput(DEMO_CSR_PEM);
    setError(null);
  }, []);

  const handleClear = useCallback(() => {
    setCsrInput("");
    setResult(null);
    setError(null);
  }, []);


  useEffect(() => {
    if (result && resultRef.current) {
      resultRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [result]);

  return (
    <>
      <div className="bg-glow" />
      <div className="app-container">
        <header className="app-header">
          <div className="logo">
            <span className="icon">&#x1F512;</span>
            <h1>CSR Decoder</h1>
          </div>
          <p className="subtitle">
            SSL/TLS 証明書署名要求 (CSR) のデコードと解析
          </p>
        </header>

        <main className="app-main">
          <section className="card input-card">
            <div className="card-header">
              <h2>CSR (PEM形式) を入力</h2>
              <div className="action-buttons-mini">
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={handleLoadDemo}
                  title="テスト用のCSRデータを入力します"
                >
                  デモデータをロード
                </button>
                <button
                  className="btn btn-tertiary btn-sm"
                  onClick={handleClear}
                  title="入力をクリアします"
                >
                  クリア
                </button>
              </div>
            </div>

            <div className="textarea-wrapper">
              <textarea
                value={csrInput}
                onChange={(e) => setCsrInput(e.target.value)}
                placeholder={
                  "-----BEGIN CERTIFICATE REQUEST-----\nここにCSRのPEMデータを貼り付けてください...\n-----END CERTIFICATE REQUEST-----"
                }
                spellCheck={false}
              />
            </div>

            <button
              className="btn btn-primary btn-block"
              onClick={handleAnalyze}
            >
              <span className="btn-text">CSRを解析する</span>
              <span className="btn-icon">&#x26A1;</span>
            </button>
          </section>

          {error && <ErrorAlert message={error} />}

          <div ref={resultRef}>
            {result && <ResultDisplay result={result} />}
          </div>
        </main>

        <footer className="app-footer">
          <p>
            解析はすべてブラウザ上で安全に行われ、データがサーバーに送信されることはありません。
          </p>
        </footer>
      </div>
    </>
  );
}

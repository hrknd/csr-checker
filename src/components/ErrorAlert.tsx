"use client";

export default function ErrorAlert({ message }: { message: string }) {
  return (
    <div className="error-alert">
      <span className="error-icon">&#x26A0;&#xFE0F;</span>
      <span className="error-text">{message}</span>
    </div>
  );
}

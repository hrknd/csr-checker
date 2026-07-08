/**
 * SSL CSR Analyzer & Decoder
 * Application Logic using node-forge
 */

// UI Elements
const el = {
  csrInput: document.getElementById('csr-input'),
  btnAnalyze: document.getElementById('btn-analyze'),
  btnDemo: document.getElementById('btn-demo'),
  btnClear: document.getElementById('btn-clear'),
  resultContainer: document.getElementById('result-container'),
  errorContainer: document.getElementById('error-container'),
  errorMessage: document.getElementById('error-message'),
  validationBadge: document.getElementById('validation-badge'),
  statSignature: document.getElementById('stat-signature'),
  statAlgorithm: document.getElementById('stat-algorithm'),
  statKeySize: document.getElementById('stat-key-size'),
  subjectTableBody: document.getElementById('subject-table-body'),
  extensionsSection: document.getElementById('extensions-section'),
  extensionsList: document.getElementById('extensions-list'),
  publicKeyPem: document.getElementById('public-key-pem'),
};

// OID to Japanese Labels Mapping
const OID_LABELS = {
  '2.5.4.3': { name: 'コモンネーム (CN)', desc: '証明書を適用するドメイン名、またはホスト名' },
  'commonName': { name: 'コモンネーム (CN)', desc: '証明書を適用するドメイン名、またはホスト名' },
  
  '2.5.4.6': { name: '国名 (C)', desc: '申請組織が登録されている国の国コード (2文字)' },
  'countryName': { name: '国名 (C)', desc: '申請組織が登録されている国の国コード (2文字)' },
  
  '2.5.4.8': { name: '都道府県 (ST)', desc: '申請組織の所在地（州、都道府県など）' },
  'stateOrProvinceName': { name: '都道府県 (ST)', desc: '申請組織の所在地（州、都道府県など）' },
  
  '2.5.4.7': { name: '市区町村 (L)', desc: '申請組織の所在地（市区町村）' },
  'localityName': { name: '市区町村 (L)', desc: '申請組織の所在地（市区町村）' },
  
  '2.5.4.10': { name: '組織名 (O)', desc: '申請組織の正式な名称（会社名など）' },
  'organizationName': { name: '組織名 (O)', desc: '申請組織の正式な名称（会社名など）' },
  
  '2.5.4.11': { name: '部署名 (OU)', desc: '組織内の部署名やグループ名（IT部門など）' },
  'organizationalUnitName': { name: '部署名 (OU)', desc: '組織内の部署名やグループ名（IT部門など）' },
  
  '1.2.840.113549.1.9.1': { name: 'メールアドレス', desc: '管理者または技術担当者のメールアドレス' },
  'emailAddress': { name: 'メールアドレス', desc: '管理者または技術担当者のメールアドレス' }
};

// Demo CSR PEM Data (Valid RSA 2048-bit with SANs)
const DEMO_CSR_PEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIDITCCAgkCAQAwezEbMBkGA1UEAxMSc2FtcGxlLmV4YW1wbGUuY29tMQswCQYD
VQQGEwJKUDEOMAwGA1UECBMFVG9reW8xEDAOBgNVBAcTB0NoaXlvZGExFTATBgNV
BAoTDEV4YW1wbGUgSW5jLjEWMBQGA1UECxMNSVQgRGVwYXJ0bWVudDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANv/lUjs5inv0Y4MV9/0yfYvmmyBi2Az
Rjl9QSJ2wFf8yblkWqUpnvQtk9rxPt9ikNJRS3o5dSm296hIuk3eiquzcYsVKj/k
v57BnR85UVxBlkRVpTjv+EkO7Qm0njVhZ6Wo/1BXx+qZwyp/gF9Hpn22mdcNkQBv
p+a/x9LEf7a4jbZoiLFgnzWPrZzO2q74pJW1h2DUQyCk85kB9DrGiME7flxeCJOM
4/X3pmK8mr8G7FQCGoJ6DfwhRYUZGgrwvkCn69xPhYegRr6dbnxx06Zizxlx+3k1
D6lUg9hJe3xTgsxgq9C+RIoLsNG/u0DP7hozajYqnwnA8Ua0Rqar3C0CAwEAAaBh
MF8GCSqGSIb3DQEJDjFSMFAwTgYDVR0RBEcwRYISc2FtcGxlLmV4YW1wbGUuY29t
ghZ3d3cuc2FtcGxlLmV4YW1wbGUuY29tghdtYWlsLnNhbXBsZS5leGFtcGxlLmNv
bTANBgkqhkiG9w0BAQUFAAOCAQEAuLQcHl3hdpDaF9puxG6ujVx8UnNwdtC8biYE
xiQPAp2RU+PL7iwrVYO9wsrhiLjflEchUsku2dfctWQptqIAFnDXJwcdFQtOM+KI
L6Jc1H+kekIBYjZZVkoMQhLODsA4iRG8zgjPtk8xbK1Vf+u0rodeLVBma7YB4CnA
2fCWCbaeBfv3O3Vn0tjtWjEpfnaVAIGL5zs3YZuJMqPI0yIJxWOi0jzZAN0tW1e5
+AhCu83bgSa2rSGdRZTx+V9gHqZ58r9sMo4SzT5p1OtO0EmKuSKmm42n40qIIPch
aOCJfWkFPaTtI9EnnZ+VtVy/Z74FP9UcUcPO3xAcRTQRVL+XhA==
-----END CERTIFICATE REQUEST-----`;

// Event Listeners
el.btnAnalyze.addEventListener('click', handleAnalyze);
el.btnDemo.addEventListener('click', handleLoadDemo);
el.btnClear.addEventListener('click', handleClear);

// Initialize with Demo Data on Load
window.addEventListener('DOMContentLoaded', () => {
  // プレースホルダーとして見せるのではなく、最初からデモをセットして解析しておく
  handleLoadDemo();
  handleAnalyze();
});

// Load Demo CSR
function handleLoadDemo() {
  el.csrInput.value = DEMO_CSR_PEM;
  hideError();
}

// Clear Inputs & Outputs
function handleClear() {
  el.csrInput.value = '';
  el.resultContainer.classList.add('hidden');
  hideError();
}

// Error Display Helpers
function showError(message) {
  el.errorContainer.classList.remove('hidden');
  el.errorMessage.textContent = message;
  el.resultContainer.classList.add('hidden');
}

function hideError() {
  el.errorContainer.classList.add('hidden');
}

// Main Analyze Logic
function handleAnalyze() {
  hideError();
  const rawPem = el.csrInput.value.trim();

  if (!rawPem) {
    showError('CSRデータをテキストエリアに入力してください。');
    return;
  }

  // Validate basic PEM structure before passing to node-forge
  if (!rawPem.includes('-----BEGIN CERTIFICATE REQUEST-----') || 
      !rawPem.includes('-----END CERTIFICATE REQUEST-----')) {
    showError('無効なフォーマットです。CSRは "-----BEGIN CERTIFICATE REQUEST-----" で始まり "-----END CERTIFICATE REQUEST-----" で終わる必要があります。');
    return;
  }

  try {
    // Parse CSR using node-forge
    const csr = forge.pki.certificationRequestFromPem(rawPem);

    // 1. Signature validation
    const isSignatureValid = csr.verify();
    updateSignatureStatus(isSignatureValid);

    // 2. Public Key algorithm & size
    updatePublicKeyInfo(csr.publicKey);

    // 3. Subject Attributes
    updateSubjectAttributes(csr.subject.attributes);

    // 4. Extension Requests (SANs, etc.)
    updateExtensions(csr);

    // Show result container
    el.resultContainer.classList.remove('hidden');
    
    // Smooth scroll to results
    el.resultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  } catch (error) {
    console.error(error);
    showError(`CSRの解析に失敗しました。データが破損しているか、非対応の暗号方式の可能性があります。\n詳細: ${error.message}`);
  }
}

// Update Signature UI
function updateSignatureStatus(isValid) {
  if (isValid) {
    el.validationBadge.className = 'badge badge-valid';
    el.validationBadge.textContent = '署名検証: 有効';
    
    el.statSignature.className = 'status-value color-success';
    el.statSignature.textContent = '検証成功 (改ざんなし)';
  } else {
    el.validationBadge.className = 'badge badge-invalid';
    el.validationBadge.textContent = '署名検証: 無効';
    
    el.statSignature.className = 'status-value color-danger';
    el.statSignature.textContent = '検証失敗 (不整合)';
  }
}

// Update Public Key Info UI
function updatePublicKeyInfo(publicKey) {
  let algorithm = '不明';
  let sizeText = '-';

  if (publicKey.n) {
    algorithm = 'RSA';
    sizeText = `${publicKey.n.bitLength()} bits`;
  } else if (publicKey.k) {
    // ECDSA or other
    algorithm = 'EC (Elliptic Curve)';
    sizeText = publicKey.curve ? `${publicKey.curve} curve` : 'サイズ不明';
  }

  el.statAlgorithm.textContent = algorithm;
  el.statKeySize.textContent = sizeText;

  // Render PEM representation of Public Key
  try {
    const pubKeyPem = forge.pki.publicKeyToPem(publicKey);
    el.publicKeyPem.textContent = pubKeyPem.trim();
  } catch (e) {
    el.publicKeyPem.textContent = '公開鍵PEMの書き出しに失敗しました。';
  }
}

// Update Subject Table
function updateSubjectAttributes(attributes) {
  el.subjectTableBody.innerHTML = '';

  if (!attributes || attributes.length === 0) {
    const emptyRow = `<tr><td colspan="3" style="text-align: center;">属性情報がありません</td></tr>`;
    el.subjectTableBody.innerHTML = emptyRow;
    return;
  }

  attributes.forEach(attr => {
    // node-forge provides attribute type/name/value
    const key = attr.type || attr.name;
    const value = attr.value;
    
    // Map OID or ShortName to friendly Japanese text
    const mapping = OID_LABELS[key] || { name: attr.shortName || attr.name || key, desc: 'その他の属性項目' };
    
    const row = document.createElement('tr');
    
    // OID tag
    const oidDisplay = attr.type ? `<span class="oid-tag">OID: ${attr.type}</span>` : '';
    
    row.innerHTML = `
      <td>
        <strong>${escapeHtml(mapping.name)}</strong>
        ${oidDisplay}
      </td>
      <td style="font-family: monospace; word-break: break-all;">${escapeHtml(value)}</td>
      <td style="font-size: 0.85rem; color: var(--text-muted);">${escapeHtml(mapping.desc)}</td>
    `;
    
    el.subjectTableBody.appendChild(row);
  });
}

// Update Extension Requests (such as SANs)
function updateExtensions(csr) {
  el.extensionsList.innerHTML = '';
  
  // Extension attributes in node-forge CSR
  const extAttribute = csr.getAttribute({ name: 'extensionRequest' }) || 
                       csr.getAttribute({ type: forge.pki.oids.extensionRequest });
  
  if (!extAttribute || !extAttribute.extensions || extAttribute.extensions.length === 0) {
    el.extensionsSection.classList.add('hidden');
    return;
  }

  el.extensionsSection.classList.remove('hidden');

  extAttribute.extensions.forEach(ext => {
    const extItem = document.createElement('div');
    extItem.className = 'extension-item';

    let extName = ext.name || ext.id || '未知の拡張属性';
    let extValue = '';

    // Handle specific extensions
    if (extName === 'subjectAltName' || ext.id === forge.pki.oids.subjectAltName) {
      extName = 'サブジェクト代替名 (Subject Alternative Names: SANs)';
      if (ext.altNames && ext.altNames.length > 0) {
        extValue = ext.altNames.map(name => {
          const typeLabel = getAltNameTypeLabel(name.type);
          return `${typeLabel}: ${name.value}`;
        }).join('\n');
      } else {
        extValue = '代替名の値が空です';
      }
    } else {
      // General rendering
      extValue = typeof ext.value === 'string' ? ext.value : JSON.stringify(ext.value, null, 2);
    }

    extItem.innerHTML = `
      <div class="extension-name">${escapeHtml(extName)}</div>
      <div class="extension-value">${escapeHtml(extValue)}</div>
    `;

    el.extensionsList.appendChild(extItem);
  });
}

// Helper to resolve SAN AltName Type to string
function getAltNameTypeLabel(type) {
  // AltName Types: 2 is DNSName, 7 is IPAddress, 1 is RFC822Name (Email), etc.
  switch (type) {
    case 1: return 'Email';
    case 2: return 'DNS';
    case 6: return 'URI';
    case 7: return 'IP';
    default: return `Type-${type}`;
  }
}

// Simple HTML Escaper
function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[tag] || tag));
}

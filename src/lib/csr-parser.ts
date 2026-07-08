import forge from "node-forge";

export interface SubjectAttribute {
  name: string;
  value: string;
  oid: string;
  description: string;
}

export interface AltName {
  type: number;
  typeLabel: string;
  value: string;
}

export interface Extension {
  name: string;
  altNames?: AltName[];
  rawValue?: string;
}

export interface CsrResult {
  signatureValid: boolean;
  algorithm: string;
  keySize: string;
  subject: SubjectAttribute[];
  extensions: Extension[];
  publicKeyPem: string;
}

const OID_LABELS: Record<string, { name: string; desc: string }> = {
  "2.5.4.3": {
    name: "コモンネーム (CN)",
    desc: "証明書を適用するドメイン名、またはホスト名",
  },
  commonName: {
    name: "コモンネーム (CN)",
    desc: "証明書を適用するドメイン名、またはホスト名",
  },
  "2.5.4.6": {
    name: "国名 (C)",
    desc: "申請組織が登録されている国の国コード (2文字)",
  },
  countryName: {
    name: "国名 (C)",
    desc: "申請組織が登録されている国の国コード (2文字)",
  },
  "2.5.4.8": {
    name: "都道府県 (ST)",
    desc: "申請組織の所在地（州、都道府県など）",
  },
  stateOrProvinceName: {
    name: "都道府県 (ST)",
    desc: "申請組織の所在地（州、都道府県など）",
  },
  "2.5.4.7": {
    name: "市区町村 (L)",
    desc: "申請組織の所在地（市区町村）",
  },
  localityName: {
    name: "市区町村 (L)",
    desc: "申請組織の所在地（市区町村）",
  },
  "2.5.4.10": {
    name: "組織名 (O)",
    desc: "申請組織の正式な名称（会社名など）",
  },
  organizationName: {
    name: "組織名 (O)",
    desc: "申請組織の正式な名称（会社名など）",
  },
  "2.5.4.11": {
    name: "部署名 (OU)",
    desc: "組織内の部署名やグループ名（IT部門など）",
  },
  organizationalUnitName: {
    name: "部署名 (OU)",
    desc: "組織内の部署名やグループ名（IT部門など）",
  },
  "1.2.840.113549.1.9.1": {
    name: "メールアドレス",
    desc: "管理者または技術担当者のメールアドレス",
  },
  emailAddress: {
    name: "メールアドレス",
    desc: "管理者または技術担当者のメールアドレス",
  },
};

function getAltNameTypeLabel(type: number): string {
  switch (type) {
    case 1:
      return "Email";
    case 2:
      return "DNS";
    case 6:
      return "URI";
    case 7:
      return "IP";
    default:
      return `Type-${type}`;
  }
}

export function parseCSR(pem: string): CsrResult {
  const csr = forge.pki.certificationRequestFromPem(pem);

  const signatureValid = csr.verify();

  let algorithm = "不明";
  let keySize = "-";
  if (csr.publicKey) {
    const rsaKey = csr.publicKey as forge.pki.rsa.PublicKey;
    if (rsaKey.n) {
      algorithm = "RSA";
      keySize = `${rsaKey.n.bitLength()} bits`;
    }
  }

  let publicKeyPem: string;
  try {
    publicKeyPem = forge.pki.publicKeyToPem(csr.publicKey!).trim();
  } catch {
    publicKeyPem = "公開鍵PEMの書き出しに失敗しました。";
  }

  const subject: SubjectAttribute[] = csr.subject.attributes.map((attr) => {
    const key = attr.type || attr.name || "";
    const mapping = OID_LABELS[key] || {
      name: attr.shortName || attr.name || key,
      desc: "その他の属性項目",
    };
    return {
      name: mapping.name,
      value: attr.value as string,
      oid: attr.type || "",
      description: mapping.desc,
    };
  });

  const extensions: Extension[] = [];
  const extAttribute =
    csr.getAttribute({ name: "extensionRequest" }) ||
    csr.getAttribute({ type: forge.pki.oids.extensionRequest });

  if (extAttribute?.extensions) {
    for (const ext of extAttribute.extensions) {
      if (
        ext.name === "subjectAltName" ||
        ext.id === forge.pki.oids.subjectAltName
      ) {
        const altNames: AltName[] = (ext.altNames || []).map(
          (an: { type: number; value: string }) => ({
            type: an.type,
            typeLabel: getAltNameTypeLabel(an.type),
            value: an.value,
          })
        );
        extensions.push({
          name: "サブジェクト代替名 (Subject Alternative Names: SANs)",
          altNames,
        });
      } else {
        extensions.push({
          name: ext.name || ext.id || "未知の拡張属性",
          rawValue:
            typeof ext.value === "string"
              ? ext.value
              : JSON.stringify(ext.value, null, 2),
        });
      }
    }
  }

  return {
    signatureValid,
    algorithm,
    keySize,
    subject,
    extensions,
    publicKeyPem,
  };
}

export const DEMO_CSR_PEM = `-----BEGIN CERTIFICATE REQUEST-----
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

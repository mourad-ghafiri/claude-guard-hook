import * as path from "node:path";

/**
 * Generates mock placeholder content for blocked files.
 * Returns content that looks realistic but contains no real data.
 */
export function generateMockContent(filePath: string): string {
  const basename = path.basename(filePath);
  const ext = path.extname(filePath).toLowerCase();
  const dir = path.dirname(filePath);

  // .env files
  if (basename.startsWith(".env")) {
    return [
      "# Environment variables",
      "# [claude-guard] This file is protected. Content replaced with mock values.",
      "",
      "NODE_ENV={{GUARD:PROTECTED_VALUE}}",
      "PORT={{GUARD:PROTECTED_VALUE}}",
      "DATABASE_URL={{GUARD:PROTECTED_VALUE}}",
      "API_KEY={{GUARD:PROTECTED_VALUE}}",
      "SECRET_KEY={{GUARD:PROTECTED_VALUE}}",
      "",
    ].join("\n");
  }

  // SSH keys
  if (dir.includes(".ssh") || basename.startsWith("id_")) {
    if (ext === ".pub") {
      return "ssh-ed25519 {{GUARD:PROTECTED_VALUE}} user@host\n";
    }
    if (basename === "config") {
      return [
        "# SSH config",
        "# [claude-guard] This file is protected. Content replaced with mock values.",
        "",
        "Host *",
        "  IdentityFile {{GUARD:PROTECTED_VALUE}}",
        "  User {{GUARD:PROTECTED_VALUE}}",
        "",
      ].join("\n");
    }
    if (basename === "known_hosts" || basename === "authorized_keys") {
      return `# [claude-guard] This file is protected. Content replaced with mock values.\n`;
    }
    return [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "{{GUARD:PROTECTED_VALUE}}",
      "-----END OPENSSH PRIVATE KEY-----",
      "",
    ].join("\n");
  }

  // AWS credentials/config
  if (dir.includes(".aws")) {
    if (basename === "credentials") {
      return [
        "# [claude-guard] This file is protected. Content replaced with mock values.",
        "[default]",
        "aws_access_key_id = {{GUARD:PROTECTED_VALUE}}",
        "aws_secret_access_key = {{GUARD:PROTECTED_VALUE}}",
        "",
      ].join("\n");
    }
    if (basename === "config") {
      return [
        "# [claude-guard] This file is protected. Content replaced with mock values.",
        "[default]",
        "region = {{GUARD:PROTECTED_VALUE}}",
        "output = json",
        "",
      ].join("\n");
    }
  }

  // Certificates and keys
  if (ext === ".pem" || ext === ".key") {
    return [
      "-----BEGIN PRIVATE KEY-----",
      "{{GUARD:PROTECTED_VALUE}}",
      "-----END PRIVATE KEY-----",
      "",
    ].join("\n");
  }
  if (ext === ".p12" || ext === ".pfx" || ext === ".jks") {
    return "# [claude-guard] Binary certificate file. Content blocked.\n";
  }

  // Docker config
  if (dir.includes(".docker") && basename === "config.json") {
    return JSON.stringify({
      auths: {
        "registry.example.com": {
          auth: "{{GUARD:PROTECTED_VALUE}}",
        },
      },
    }, null, 2) + "\n";
  }

  // Kube config
  if (dir.includes(".kube") && basename === "config") {
    return [
      "# [claude-guard] This file is protected. Content replaced with mock values.",
      "apiVersion: v1",
      "kind: Config",
      "clusters:",
      "- cluster:",
      "    server: {{GUARD:PROTECTED_VALUE}}",
      "    certificate-authority-data: {{GUARD:PROTECTED_VALUE}}",
      "  name: default",
      "users:",
      "- name: default",
      "  user:",
      "    token: {{GUARD:PROTECTED_VALUE}}",
      "",
    ].join("\n");
  }

  // .npmrc / .netrc
  if (basename === ".npmrc") {
    return [
      "# [claude-guard] This file is protected. Content replaced with mock values.",
      "//registry.npmjs.org/:_authToken={{GUARD:PROTECTED_VALUE}}",
      "",
    ].join("\n");
  }
  if (basename === ".netrc") {
    return [
      "# [claude-guard] This file is protected. Content replaced with mock values.",
      "machine github.com",
      "  login {{GUARD:PROTECTED_VALUE}}",
      "  password {{GUARD:PROTECTED_VALUE}}",
      "",
    ].join("\n");
  }

  // .pgpass
  if (basename === ".pgpass") {
    return "# [claude-guard] This file is protected. Content replaced with mock values.\n{{GUARD:PROTECTED_VALUE}}:5432:*:{{GUARD:PROTECTED_VALUE}}:{{GUARD:PROTECTED_VALUE}}\n";
  }

  // GCP credentials
  if (basename === "serviceAccountKey.json" || basename === "application_default_credentials.json") {
    return JSON.stringify({
      type: "service_account",
      project_id: "{{GUARD:PROTECTED_VALUE}}",
      private_key_id: "{{GUARD:PROTECTED_VALUE}}",
      private_key: "{{GUARD:PROTECTED_VALUE}}",
      client_email: "{{GUARD:PROTECTED_VALUE}}",
      client_id: "{{GUARD:PROTECTED_VALUE}}",
    }, null, 2) + "\n";
  }

  // JSON files (generic)
  if (ext === ".json") {
    return JSON.stringify({
      _notice: "[claude-guard] This file is protected. Content replaced with mock values.",
      credentials: "{{GUARD:PROTECTED_VALUE}}",
    }, null, 2) + "\n";
  }

  // Default fallback
  return `# [claude-guard] This file is protected. Content replaced with mock values.\n# File: ${basename}\n{{GUARD:PROTECTED_VALUE}}\n`;
}

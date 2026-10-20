// Chargement du .env (robuste) + accès aux variables d'environnement.
// Ce module DOIT être importé avant tout autre module de config.

import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// stone-server/.env  (src/config → ../.. = racine du serveur)
export const envPath = path.join(__dirname, "..", "..", ".env");

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;

  try {
    const lines = fs.readFileSync(filePath, "utf-8").split(/\r?\n/);

    for (const line of lines) {
      const trimmed = line.trim();

      if (!trimmed || trimmed.startsWith("#")) continue;

      const idx = trimmed.indexOf("=");
      if (idx === -1) continue;

      const key = trimmed.slice(0, idx).trim();
      let value = trimmed.slice(idx + 1).trim();

      value = value.replace(/^(['"])(.*)\1$/, "$2");

      if (key && !(key in process.env)) {
        process.env[key] = value;
      }
    }
  } catch (error) {
    console.error(`Erreur lors du chargement de ${filePath}:`, error.message);
  }
}

loadEnvFile(envPath);

export function env(name) {
  const value = process.env[name];
  return typeof value === "string" ? value.trim() : undefined;
}

export const IS_PRODUCTION = env("NODE_ENV") === "production";

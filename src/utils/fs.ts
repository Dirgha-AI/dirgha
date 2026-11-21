import { dirname, join, relative, resolve, sep } from "node:path";
import { realpathSync } from "node:fs";

/**
 * Canonicalize a path even if leaf segments do not exist yet by walking up to
 * the nearest existing ancestor, resolving symlinks via realpathSync, and
 * re-appending the remaining relative segments.
 */
export function canonicalizePath(targetPath: string): string {
  const abs = resolve(targetPath);
  try {
    return realpathSync(abs);
  } catch {
    const tail: string[] = [];
    let current = abs;
    while (true) {
      const parent = dirname(current);
      if (parent === current) return abs;
      tail.unshift(relative(parent, current));
      current = parent;
      try {
        const realAncestor = realpathSync(current);
        return join(realAncestor, ...tail);
      } catch {
        // continue walking up
      }
    }
  }
}

export function isValidCwdPath(
  cwd: string,
  relativePath: string,
  opts?: { allowOutside?: boolean },
):
  | { valid: false; error: string }
  | { valid: true; resolved: string; cwdNorm: string } {
  const resolved = resolve(cwd, relativePath);
  const realCwd = canonicalizePath(cwd);
  const realTarget = canonicalizePath(resolved);
  const cwdNorm = realCwd.endsWith(sep) ? realCwd : realCwd + sep;
  if (opts?.allowOutside) {
    return { valid: true, resolved, cwdNorm };
  }
  if (!realTarget.startsWith(cwdNorm) && realTarget !== realCwd) {
    return { valid: false, error: `path escapes workspace: ${relativePath}` };
  }
  return { valid: true, resolved: realTarget, cwdNorm };
}

export function decodeLiteralUnicodeEscapes(s: string): string {
  return s.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => {
    const cp = parseInt(hex, 16);
    if (
      (cp >= 0x20 && cp <= 0x7e) ||
      cp === 0x0a ||
      cp === 0x0d ||
      cp === 0x09
    ) {
      return String.fromCodePoint(cp);
    }
    return _;
  });
}

export function isBinary(buf: Buffer): boolean {
  const sample = buf.subarray(0, Math.min(buf.length, 8192));
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return true;
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) return true;
  let nonPrintable = 0;
  for (const byte of sample) {
    if (byte === 0) return true;
    if (byte < 0x09 || (byte > 0x0d && byte < 0x20)) nonPrintable++;
  }
  return sample.length > 0 && nonPrintable / sample.length > 0.3;
}

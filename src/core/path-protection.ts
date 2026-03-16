import * as path from "node:path";
import { minimatch } from "minimatch";
import { GuardConfig } from "../config/types.js";

/**
 * Checks if a file path matches any protected file or folder pattern.
 */
export function isPathProtected(
  relativePath: string,
  absolutePath: string,
  config: GuardConfig,
): boolean {
  const basename = path.basename(absolutePath);
  const matchOpts = { dot: true };

  // Check protected files
  for (const pattern of config.protectedFiles) {
    if (
      minimatch(relativePath, pattern, matchOpts) ||
      minimatch(basename, pattern, matchOpts) ||
      minimatch(absolutePath, pattern, matchOpts)
    ) {
      return true;
    }
  }

  // Check protected folders — block any file inside a protected folder
  const folders = config.protectedFolders ?? [];
  for (const pattern of folders) {
    const dirPath = path.dirname(relativePath);
    const absDirPath = path.dirname(absolutePath);
    if (
      minimatch(dirPath, pattern, matchOpts) ||
      minimatch(absDirPath, pattern, matchOpts) ||
      minimatch(relativePath, pattern + "/**", matchOpts) ||
      minimatch(absolutePath, pattern + "/**", matchOpts)
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Checks if a directory path is inside a protected folder.
 */
export function isInsideProtectedFolder(
  dirPath: string,
  config: GuardConfig,
  cwd: string,
): boolean {
  const resolvedDir = path.resolve(cwd, dirPath);
  const relativeDir = path.relative(cwd, resolvedDir);
  const matchOpts = { dot: true };

  for (const pattern of config.protectedFolders ?? []) {
    if (
      minimatch(relativeDir, pattern, matchOpts) ||
      minimatch(resolvedDir, pattern, matchOpts) ||
      minimatch(relativeDir, pattern + "/**", matchOpts) ||
      minimatch(resolvedDir, pattern + "/**", matchOpts)
    ) {
      return true;
    }
  }

  return false;
}

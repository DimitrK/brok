#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const targetRoot = process.argv[2];

if (!targetRoot) {
  console.error('Usage: node ./scripts/fix-esm-specifiers.mjs <target-root>');
  process.exit(1);
}

const normalizedTargetRoot = path.resolve(targetRoot);
const specifierRegexes = [
  /\bfrom\s+(['"])(\.\.?\/[^'"]+)\1/gu,
  /\bimport\(\s*(['"])(\.\.?\/[^'"]+)\1\s*\)/gu
];

const hasRuntimeExtension = specifier =>
  specifier.endsWith('.js') ||
  specifier.endsWith('.mjs') ||
  specifier.endsWith('.cjs') ||
  specifier.endsWith('.json') ||
  specifier.endsWith('.node');

const resolveSpecifierReplacement = ({specifier, fileDir}) => {
  if (hasRuntimeExtension(specifier)) {
    return null;
  }

  const basePath = path.resolve(fileDir, specifier);
  const fileCandidate = `${basePath}.js`;
  if (fs.existsSync(fileCandidate) && fs.statSync(fileCandidate).isFile()) {
    return `${specifier}.js`;
  }

  const indexCandidate = path.join(basePath, 'index.js');
  if (fs.existsSync(indexCandidate) && fs.statSync(indexCandidate).isFile()) {
    return `${specifier.replace(/\/$/u, '')}/index.js`;
  }

  return null;
};

const rewriteFile = filePath => {
  const original = fs.readFileSync(filePath, 'utf8');
  let updated = original;
  const fileDir = path.dirname(filePath);

  for (const regex of specifierRegexes) {
    updated = updated.replace(regex, (fullMatch, quote, specifier) => {
      const replacement = resolveSpecifierReplacement({
        specifier,
        fileDir
      });
      if (!replacement) {
        return fullMatch;
      }
      return fullMatch.replace(`${quote}${specifier}${quote}`, `${quote}${replacement}${quote}`);
    });
  }

  if (updated !== original) {
    fs.writeFileSync(filePath, updated, 'utf8');
  }
};

const visitedDirectories = new Set();

const walkJsFiles = directory => {
  if (!fs.existsSync(directory)) {
    return;
  }

  const stat = fs.statSync(directory);
  if (!stat.isDirectory()) {
    return;
  }

  const realDirectory = fs.realpathSync(directory);
  if (visitedDirectories.has(realDirectory)) {
    return;
  }
  visitedDirectories.add(realDirectory);

  const entries = fs.readdirSync(realDirectory, {withFileTypes: true});
  for (const entry of entries) {
    const entryPath = path.join(realDirectory, entry.name);
    if (entry.isDirectory()) {
      walkJsFiles(entryPath);
      continue;
    }
    if (entry.isSymbolicLink()) {
      const linkPath = fs.realpathSync(entryPath);
      if (fs.existsSync(linkPath) && fs.statSync(linkPath).isDirectory()) {
        walkJsFiles(linkPath);
      }
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.js')) {
      rewriteFile(entryPath);
    }
  }
};

walkJsFiles(path.join(normalizedTargetRoot, 'dist'));
walkJsFiles(path.join(normalizedTargetRoot, 'node_modules', '@broker-interceptor'));
walkJsFiles(path.join(normalizedTargetRoot, 'node_modules', '.pnpm'));

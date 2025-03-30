#!/usr/bin/env node
import { copyFileSync, chmodSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';

function main() {
  const hookPath = join('.git', 'hooks');
  const preCommitPath = join(hookPath, 'pre-commit');
  const sourcePath = join('scripts', 'pre-commit.ts');

  // Create hooks directory if it doesn't exist
  if (!existsSync(hookPath)) {
    mkdirSync(hookPath, { recursive: true });
  }

  try {
    // Copy the pre-commit script
    copyFileSync(sourcePath, preCommitPath);
    
    // Make it executable
    chmodSync(preCommitPath, '755');
    
    console.log('✅ Pre-commit hook installed successfully');
  } catch (error) {
    console.error('❌ Failed to install pre-commit hook:', error);
    process.exit(1);
  }
}

main(); 
#!/usr/bin/env node
import { GitScanner } from '../src/scanners/GitScanner';
import { Logger } from '../src/utils/Logger';

async function main() {
  const logger = new Logger('info');
  const scanner = new GitScanner(undefined, undefined, logger);

  try {
    const { results, shouldBlock } = await scanner.runPreCommitScan();

    if (shouldBlock) {
      logger.error(`
🚫 Commit blocked: ${results.length} potential token(s) found.
Please review the findings above and:
1. Remove any real tokens from the staged files
2. If they are false positives, you can:
   - Add custom ignore patterns to .tokenguardianrc
   - Use // tokenguardian:ignore to ignore specific lines
3. Run git commit again after fixing the issues
      `);
      process.exit(1);
    }

    logger.info('✅ No tokens found in staged files');
    process.exit(0);
  } catch (error) {
    logger.error('Error running pre-commit scan:', { error });
    process.exit(1);
  }
}

main(); 
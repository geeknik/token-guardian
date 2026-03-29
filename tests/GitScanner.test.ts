import fs from 'fs';
import os from 'os';
import path from 'path';
import { GitScanner } from '../src/scanners/GitScanner';

describe('GitScanner', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'token-guardian-git-scanner-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  test('ignores root-level test files that match the default ignore patterns', async () => {
    const scanner = new GitScanner();
    const testFile = path.join(tempDir, 'fixture.test.ts');
    fs.writeFileSync(testFile, "const token = 'AKIAIOSFODNN7EXAMPLE';\n", 'utf8');

    const internals = scanner as unknown as {
      scanFile: (filepath: string) => Promise<unknown[]>;
    };

    await expect(internals.scanFile(testFile)).resolves.toEqual([]);
  });

  test('ignores files inside tests directories', async () => {
    const scanner = new GitScanner();
    const testsDir = path.join(tempDir, 'tests');
    const testFile = path.join(testsDir, 'secrets.ts');
    fs.mkdirSync(testsDir, { recursive: true });
    fs.writeFileSync(testFile, "const token = 'AKIAIOSFODNN7EXAMPLE';\n", 'utf8');

    const internals = scanner as unknown as {
      scanFile: (filepath: string) => Promise<unknown[]>;
    };

    await expect(internals.scanFile(testFile)).resolves.toEqual([]);
  });

  test('scans non-ignored files even when token regexes are not declared global', async () => {
    const scanner = new GitScanner();
    const sourceFile = path.join(tempDir, 'src', 'secrets.ts');
    fs.mkdirSync(path.dirname(sourceFile), { recursive: true });
    fs.writeFileSync(sourceFile, "const token = 'AKIAIOSFODNN7EXAMPLE';\n", 'utf8');

    const internals = scanner as unknown as {
      scanFile: (filepath: string) => Promise<Array<{ type: string; value: string }>>;
    };

    const results = await internals.scanFile(sourceFile);

    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      type: 'aws_access_key',
      value: 'AKIAIOSFODNN7EXAMPLE'
    });
  });
});

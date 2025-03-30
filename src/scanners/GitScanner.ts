import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import { Logger } from '../utils/Logger';
import { TokenPattern } from '../interfaces/TokenPattern';
import { ScanResult } from '../interfaces/ScanResult';

const execAsync = promisify(exec);

/**
 * Default token patterns to scan for
 */
const DEFAULT_PATTERNS: TokenPattern[] = [
  {
    name: 'AWS Access Key',
    regex: /(?<![A-Za-z0-9])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9])/,
    description: 'AWS Access Key ID',
    entropyThreshold: 3.5,
    severity: 'high'
  },
  {
    name: 'AWS Secret Key',
    regex: /(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9])/,
    description: 'AWS Secret Access Key',
    entropyThreshold: 4.5,
    severity: 'high'
  },
  {
    name: 'GitHub Token',
    regex: /(?<![A-Za-z0-9])(gh[ps]_[a-zA-Z0-9]{36})(?![A-Za-z0-9])/,
    description: 'GitHub Personal Access Token',
    entropyThreshold: 4.0,
    severity: 'high'
  },
  {
    name: 'Google API Key',
    regex: /(?<![A-Za-z0-9])(AIza[0-9A-Za-z\\-_]{35})(?![A-Za-z0-9])/,
    description: 'Google API Key',
    entropyThreshold: 3.8,
    severity: 'high'
  },
  {
    name: 'JWT',
    regex: /(?<![A-Za-z0-9])([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)(?![A-Za-z0-9])/,
    description: 'JSON Web Token',
    entropyThreshold: 4.0,
    severity: 'medium',
    validate: (token: string) => {
      try {
        const [header, payload] = token.split('.').map(part => 
          JSON.parse(Buffer.from(part, 'base64url').toString())
        );
        return (
          typeof header === 'object' &&
          header !== null &&
          typeof payload === 'object' &&
          payload !== null &&
          typeof header.alg === 'string' &&
          typeof header.typ === 'string'
        );
      } catch {
        return false;
      }
    }
  }
];

/**
 * Default file patterns to ignore
 */
const DEFAULT_IGNORE_PATTERNS = [
  '**/*.test.{js,ts,jsx,tsx}',
  '**/*.spec.{js,ts,jsx,tsx}',
  '**/test/**',
  '**/tests/**',
  '**/__tests__/**',
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**'
];

export class GitScanner {
  private patterns: TokenPattern[];
  private ignorePatterns: string[];
  private logger: Logger;

  constructor(
    patterns: TokenPattern[] = DEFAULT_PATTERNS,
    ignorePatterns: string[] = DEFAULT_IGNORE_PATTERNS,
    logger?: Logger
  ) {
    this.patterns = patterns;
    this.ignorePatterns = ignorePatterns;
    this.logger = logger || new Logger('info');
  }

  /**
   * Calculate Shannon entropy of a string
   * @param str String to calculate entropy for
   * @returns Entropy value
   */
  private calculateEntropy(str: string): number {
    const len = str.length;
    const frequencies = new Map<string, number>();

    // Calculate character frequencies
    for (const char of str) {
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }

    // Calculate entropy using Shannon's formula
    return Array.from(frequencies.values()).reduce((entropy, freq) => {
      const probability = freq / len;
      return entropy - probability * Math.log2(probability);
    }, 0);
  }

  /**
   * Check if a file should be ignored
   * @param filepath File path to check
   * @returns Whether the file should be ignored
   */
  private shouldIgnoreFile(filepath: string): boolean {
    return this.ignorePatterns.some(pattern => {
      if (pattern.startsWith('**/')) {
        return filepath.includes(pattern.slice(3));
      }
      return filepath === pattern;
    });
  }

  /**
   * Get staged files for scanning
   * @returns List of staged file paths
   */
  private async getStagedFiles(): Promise<string[]> {
    const { stdout } = await execAsync('git diff --cached --name-only');
    return stdout.split('\n').filter(file => file.trim());
  }

  /**
   * Scan a single line for potential tokens
   * @param line Line to scan
   * @param lineNumber Line number
   * @param filepath File path
   * @returns Array of found tokens
   */
  private scanLine(
    line: string,
    lineNumber: number,
    filepath: string
  ): ScanResult[] {
    const results: ScanResult[] = [];

    for (const pattern of this.patterns) {
      const matches = line.matchAll(pattern.regex);
      
      for (const match of matches) {
        const token = match[1] || match[0];
        const entropy = this.calculateEntropy(token);

        // Skip if entropy is too low (likely not a real token)
        if (entropy < pattern.entropyThreshold) {
          continue;
        }

        // Validate token if pattern has a validator
        if (pattern.validate && !pattern.validate(token)) {
          continue;
        }

        // Calculate token fingerprint
        const fingerprint = createHash('sha256')
          .update(token)
          .digest('hex')
          .substring(0, 16);

        results.push({
          type: pattern.name.toLowerCase().replace(/\s+/g, '_'),
          value: token,
          description: pattern.description,
          fingerprint,
          entropy,
          location: {
            file: filepath,
            line: lineNumber,
            column: match.index || 0
          }
        });
      }
    }

    return results;
  }

  /**
   * Scan a file for potential tokens
   * @param filepath File to scan
   * @returns Scan results
   */
  private async scanFile(filepath: string): Promise<ScanResult[]> {
    if (this.shouldIgnoreFile(filepath)) {
      return [];
    }

    try {
      const content = readFileSync(filepath, 'utf8');
      const lines = content.split('\n');
      const results: ScanResult[] = [];

      for (let i = 0; i < lines.length; i++) {
        const lineResults = this.scanLine(lines[i], i + 1, filepath);
        results.push(...lineResults);
      }

      return results;
    } catch (error) {
      this.logger.error(`Error scanning file ${filepath}: ${error}`);
      return [];
    }
  }

  /**
   * Run the pre-commit scan
   * @returns Scan results and whether the commit should be blocked
   */
  public async runPreCommitScan(): Promise<{
    results: ScanResult[];
    shouldBlock: boolean;
  }> {
    const stagedFiles = await this.getStagedFiles();
    const allResults: ScanResult[] = [];

    for (const file of stagedFiles) {
      const results = await this.scanFile(file);
      allResults.push(...results);
    }

    // Log results
    if (allResults.length > 0) {
      this.logger.warn('🚨 Potential tokens found in commit:');
      for (const result of allResults) {
        this.logger.warn(`
  Token Type: ${result.type}
  Description: ${result.description}
  File: ${result.location.file}:${result.location.line}
  Fingerprint: ${result.fingerprint}
  Entropy: ${result.entropy.toFixed(2)}
  
  Please verify this is not a real token. If it is:
  1. Remove the token from the file
  2. Rotate the token immediately
  3. Check for any unauthorized usage
        `);
      }
    }

    return {
      results: allResults,
      shouldBlock: allResults.length > 0
    };
  }

  /**
   * Add a custom token pattern
   * @param pattern Pattern to add
   */
  public addPattern(pattern: TokenPattern): void {
    this.patterns.push(pattern);
  }

  /**
   * Add a custom ignore pattern
   * @param pattern Pattern to ignore
   */
  public addIgnorePattern(pattern: string): void {
    this.ignorePatterns.push(pattern);
  }
} 
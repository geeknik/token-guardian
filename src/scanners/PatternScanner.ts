import { createHash } from 'crypto';
import { ScanResult } from '../interfaces/ScanResult';
import { TokenPattern } from '../interfaces/TokenPattern';
import { Logger } from '../utils/Logger';

/**
 * Scanner that detects potential tokens and secrets in strings
 */
export class PatternScanner {
  private patterns: TokenPattern[];
  private logger: Logger;

  constructor(patterns: TokenPattern[] = [], logger?: Logger) {
    this.patterns = patterns;
    this.logger = logger || new Logger('info');
  }

  /**
   * Scans a string for potential tokens or secrets
   * @param content The string to scan
   * @param filepath The file path of the scanned content
   * @returns Results of the scan
   */
  public scan(content: string, filepath: string): ScanResult[] {
    const results: ScanResult[] = [];

    for (const pattern of this.patterns) {
      // Ensure regex is global
      const regex = pattern.regex instanceof RegExp ? 
        new RegExp(pattern.regex.source, pattern.regex.flags + (pattern.regex.flags.includes('g') ? '' : 'g')) :
        new RegExp(pattern.regex, 'g');
      
      const matches = content.matchAll(regex);
      
      for (const match of matches) {
        const token = match[1] || match[0];
        const entropy = this.calculateEntropy(token);

        // Skip if entropy is too low
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
            line: this.getLineNumber(content, match.index || 0),
            column: match.index || 0
          }
        });
      }
    }

    return results;
  }

  /**
   * Calculates Shannon entropy of a string
   * @param str The string to calculate entropy for
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
   * Gets the line number for a position in text
   * @param text The text to search in
   * @param position The position to find the line number for
   * @returns The line number (1-based)
   */
  private getLineNumber(text: string, position: number): number {
    const lines = text.slice(0, position).split('\n');
    return lines.length;
  }

  public addPattern(pattern: TokenPattern): void {
    this.patterns.push(pattern);
  }
}

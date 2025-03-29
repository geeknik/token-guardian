import { ScanResult } from '../interfaces/ScanResult';
import { TokenPatterns } from './TokenPatterns';

/**
 * Scanner that detects potential tokens and secrets in strings
 */
export class PatternScanner {
  private patterns: TokenPatterns;

  constructor() {
    this.patterns = new TokenPatterns();
  }

  /**
   * Scans a string for potential tokens or secrets
   * @param input The string to scan
   * @returns Results of the scan
   */
  public scan(input: string): ScanResult {
    const result: ScanResult = {
      found: false,
      matches: [],
      entropy: this.calculateEntropy(input)
    };

    // Get all patterns
    const allPatterns = this.patterns.getAllPatterns();

    // Check each pattern
    for (const [type, pattern] of Object.entries(allPatterns)) {
      const regex = new RegExp(pattern, 'g');
      let match;

      while ((match = regex.exec(input)) !== null) {
        const value = match[0];
        const position = match.index;
        
        // Calculate confidence based on entropy and format
        const entropy = this.calculateEntropy(value);
        let confidence = entropy / 5; // Normalize to 0-1 range (roughly)
        
        // Adjust confidence based on known formats
        if (type.includes('api_key') || type.includes('token')) {
          confidence = Math.min(confidence + 0.3, 1.0);
        }
        
        result.matches.push({
          type,
          value,
          position,
          confidence
        });
      }
    }

    result.found = result.matches.length > 0;
    return result;
  }

  /**
   * Calculates Shannon entropy of a string
   * @param str The string to calculate entropy for
   * @returns Entropy value
   */
  private calculateEntropy(str: string): number {
    const len = str.length;
    
    // Count character frequencies
    const charFreq: Record<string, number> = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      charFreq[char] = (charFreq[char] || 0) + 1;
    }
    
    // Calculate entropy
    let entropy = 0;
    for (const char of Object.keys(charFreq)) {
      const freq = charFreq[char] / len;
      entropy -= freq * Math.log2(freq);
    }
    
    return entropy;
  }
}

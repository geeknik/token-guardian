/**
 * Interface for token pattern definitions
 */
export interface TokenPattern {
  /** Name of the token pattern */
  name: string;
  /** Regular expression to match the token */
  regex: RegExp;
  /** Description of what this pattern detects */
  description: string;
  /** Minimum entropy threshold for this pattern */
  entropyThreshold: number;
  /** Severity of the pattern */
  severity: 'low' | 'medium' | 'high';
  /** Optional validation function */
  validate?: (token: string) => boolean;
} 
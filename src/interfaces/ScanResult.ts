/**
 * Interface for token scan results
 */
export interface ScanResult {
  /** Type of token found */
  type: string;
  /** The detected token value */
  value: string;
  /** Description of the token pattern */
  description: string;
  /** Token fingerprint (hashed value) */
  fingerprint: string;
  /** Calculated entropy of the token */
  entropy: number;
  /** Location where the token was found */
  location: {
    /** File path */
    file: string;
    /** Line number */
    line: number;
    /** Column number */
    column: number;
  };
}

/**
 * Results from scanning a string for potential tokens/secrets
 */
export interface ScanResult {
  /**
   * Whether any potential secrets were found
   */
  found: boolean;
  
  /**
   * Array of detected pattern matches
   */
  matches: {
    /**
     * Type of token/secret detected
     */
    type: string;
    
    /**
     * The matched string
     */
    value: string;
    
    /**
     * Position in the original string
     */
    position: number;
    
    /**
     * Confidence level (0-1) that this is a real token/secret
     */
    confidence: number;
  }[];
  
  /**
   * Entropy level of the entire input string
   */
  entropy: number;
}

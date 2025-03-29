/**
 * Result of a token rotation operation
 */
export interface RotationResult {
  /**
   * Whether the rotation was successful
   */
  success: boolean;
  
  /**
   * Message explaining the result
   */
  message: string;
  
  /**
   * New token value (if rotation succeeded)
   */
  newToken?: string;
  
  /**
   * Expiration date of the new token
   */
  newExpiry: Date | null;
}

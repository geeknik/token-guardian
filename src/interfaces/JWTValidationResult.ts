/**
 * Interface representing the result of JWT token validation
 */
export interface JWTValidationResult {
  /**
   * Whether the token is valid
   */
  isValid: boolean;

  /**
   * Error message if validation failed
   */
  error?: string;

  /**
   * Decoded token payload if validation succeeded
   */
  payload?: Record<string, any>;

  /**
   * Token expiration timestamp in seconds since epoch
   */
  expiresAt?: number;

  /**
   * Additional metadata about the validation result
   */
  metadata?: Record<string, any>;
} 
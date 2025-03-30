/**
 * Result of JWT token validation
 */
export interface JWTValidationResult {
  valid: boolean;
  error?: string;
  payload?: Record<string, any>;
  header?: Record<string, any>;
  expiresAt?: Date;
} 
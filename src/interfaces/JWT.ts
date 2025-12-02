/**
 * Result of JWT token validation
 */
export interface JWTValidationResult {
  valid: boolean;
  error?: string;
  payload?: Record<string, unknown>;
  header?: Record<string, unknown>;
  expiresAt?: Date;
}

/**
 * Configuration options for the DefaultRotator
 */
export interface DefaultRotatorConfig {
  /**
   * Secret key used for signing JWTs
   */
  secretKey: string;

  /**
   * Token expiration time in seconds
   * @default 3600 (1 hour)
   */
  expiresIn?: number;

  /**
   * Token issuer
   * @default 'token-guardian'
   */
  issuer?: string;

  /**
   * Token audience
   */
  audience?: string;

  /**
   * Additional claims to include in the token
   */
  additionalClaims?: Record<string, any>;

  /**
   * Validation options for verifying tokens
   */
  validationOptions?: {
    /**
     * Whether to verify the token expiration
     * @default true
     */
    verifyExpiration?: boolean;

    /**
     * Whether to verify the token issuer
     * @default true
     */
    verifyIssuer?: boolean;

    /**
     * Whether to verify the token audience
     * @default true
     */
    verifyAudience?: boolean;

    /**
     * Clock tolerance in seconds for expiration checks
     * @default 0
     */
    clockTolerance?: number;
  };
} 
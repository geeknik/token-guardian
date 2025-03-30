/**
 * JWT configuration options
 */
export interface JWTConfig {
  secret: string;
  expiresIn: string | number;
  algorithm: string;
}

/**
 * Retry configuration options
 */
export interface RetryOptions {
  maxRetries: number;
  initialDelayMs: number;
  maxDelayMs: number;
  backoffFactor: number;
  retryStatusCodes: number[];
}

/**
 * Default rotator configuration
 */
export interface DefaultRotatorConfig {
  jwt?: JWTConfig;
  retry?: RetryOptions;
  serviceType: string;
  rotationInterval: string;
} 
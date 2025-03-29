/**
 * Configuration options for TokenGuardian
 */
export interface GuardianConfig {
  /**
   * Services to enable token rotation for
   */
  services: string[];
  
  /**
   * Default interval for token rotation (e.g. '30d', '6h')
   */
  rotationInterval: string;
  
  /**
   * Whether to enable canary tokens by default
   */
  canaryEnabled: boolean;
  
  /**
   * Encryption key used for securing tokens at rest
   */
  encryptionKey: string;
  
  /**
   * Log level ('debug', 'info', 'warn', 'error')
   */
  logLevel: string;
}

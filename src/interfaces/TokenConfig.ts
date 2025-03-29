/**
 * Configuration options for a specific token
 */
export interface TokenConfig {
  /**
   * Whether to enable automatic rotation for this token
   */
  rotationEnabled: boolean;
  
  /**
   * Interval for token rotation (e.g. '30d', '6h')
   */
  rotationInterval: string;
  
  /**
   * Whether to embed canary markers in this token
   */
  canaryEnabled: boolean;
  
  /**
   * Type of service this token is for (e.g. 'github', 'aws')
   */
  serviceType: string;
}

import { RotationResult } from '../interfaces/RotationResult';

/**
 * Interface for service-specific token rotators
 */
export interface ServiceRotator {
  /**
   * Rotates a token for a specific service
   * @param tokenName The name/identifier of the token
   * @param currentToken The current token value
   * @returns Result of the rotation
   */
  rotateToken(tokenName: string, currentToken: string): Promise<RotationResult>;
}

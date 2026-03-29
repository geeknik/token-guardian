import { RotationResult } from '../interfaces/RotationResult';

/**
 * Interface for token rotation strategies
 */
export interface RotationStrategy {
  /**
   * Rotate a token by validating the current one and generating a new one
   * @param currentToken The current token to rotate
   * @param tokenName Optional token identifier for service-specific rotators
   * @returns A promise resolving to the rotation result
   */
  rotateToken(currentToken: string, tokenName?: string): Promise<RotationResult>;
}

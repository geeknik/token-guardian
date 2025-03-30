import { RotationResult } from '../interfaces/RotationResult';

/**
 * Interface for token rotation strategies
 */
export interface RotationStrategy {
  /**
   * Rotate a token by validating the current one and generating a new one
   * @param currentToken The current token to rotate
   * @returns A promise resolving to the rotation result
   */
  rotateToken(currentToken: string): Promise<RotationResult>;
} 
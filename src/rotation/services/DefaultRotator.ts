import { ServiceRotator } from '../ServiceRotator';
import { RotationResult } from '../../interfaces/RotationResult';

/**
 * Default rotator for generic tokens
 */
export class DefaultRotator implements ServiceRotator {
  /**
   * Default implementation for token rotation
   * @param tokenName The name/identifier of the token
   * @param currentToken The current token value
   * @returns Result indicating manual rotation is required
   */
  public async rotateToken(tokenName: string, currentToken: string): Promise<RotationResult> {
    return {
      success: false,
      message: `Automatic rotation not supported for token ${tokenName}. Please rotate manually.`,
      newExpiry: null
    };
  }
}

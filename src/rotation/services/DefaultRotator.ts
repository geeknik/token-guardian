import { sign, verify, JwtPayload } from 'jsonwebtoken';
import { RotationStrategy } from '../../rotation/RotationStrategy';
import { RotationResult } from '../../interfaces/RotationResult';
import { DefaultRotatorConfig } from '../../interfaces/DefaultRotatorConfig';
import { JWTValidationResult } from '../../interfaces/JWTValidationResult';
import { RotationError } from '../../errors/RotationError';
import { Logger } from '../../utils/Logger';

/**
 * Default implementation of token rotation using JWTs
 */
export class DefaultRotator implements RotationStrategy {
  private readonly logger: Logger;
  private readonly config: Required<DefaultRotatorConfig>;

  constructor(config: DefaultRotatorConfig) {
    this.logger = new Logger('info');
    this.config = {
      secretKey: config.secretKey,
      expiresIn: config.expiresIn ?? 3600,
      issuer: config.issuer ?? 'token-guardian',
      audience: config.audience ?? 'default',
      additionalClaims: config.additionalClaims ?? {},
      validationOptions: {
        verifyExpiration: config.validationOptions?.verifyExpiration ?? true,
        verifyIssuer: config.validationOptions?.verifyIssuer ?? true,
        verifyAudience: config.validationOptions?.verifyAudience ?? true,
        clockTolerance: config.validationOptions?.clockTolerance ?? 0
      }
    };
  }

  /**
   * Rotate a token by validating the current one and generating a new one
   */
  public async rotateToken(currentToken: string): Promise<RotationResult> {
    try {
      // Validate current token
      const validationResult = await this.validateToken(currentToken);
      if (!validationResult.isValid) {
        throw RotationError.validationError('Invalid token', { error: validationResult.error });
      }

      // Generate new token
      const newToken = await this.generateToken(validationResult.payload);
      
      // Validate new token
      const newValidationResult = await this.validateToken(newToken);
      if (!newValidationResult.isValid) {
        throw RotationError.validationError('Failed to validate new token', { error: newValidationResult.error });
      }

      return {
        success: true,
        message: 'Token rotated successfully',
        newToken,
        newExpiry: newValidationResult.expiresAt ? new Date(newValidationResult.expiresAt * 1000) : null,
        metadata: {
          issuer: this.config.issuer,
          audience: this.config.audience
        }
      };
    } catch (error) {
      if (error instanceof RotationError) {
        return {
          success: false,
          message: error.message,
          warnings: [`Rotation failed: ${error.message}`],
          metadata: error.details,
          newExpiry: null
        };
      }
      return {
        success: false,
        message: 'Failed to rotate token',
        warnings: ['Unexpected error during token rotation'],
        metadata: { error: error instanceof Error ? error.message : String(error) },
        newExpiry: null
      };
    }
  }

  /**
   * Validate a JWT token
   */
  private async validateToken(token: string): Promise<JWTValidationResult> {
    try {
      const payload = verify(token, this.config.secretKey, {
        issuer: this.config.validationOptions.verifyIssuer ? this.config.issuer : undefined,
        audience: this.config.validationOptions.verifyAudience ? this.config.audience : undefined,
        clockTolerance: this.config.validationOptions.clockTolerance,
        ignoreExpiration: !this.config.validationOptions.verifyExpiration
      }) as JwtPayload;

      return {
        isValid: true,
        payload,
        expiresAt: payload.exp
      };
    } catch (error) {
      return {
        isValid: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Generate a new JWT token
   */
  private async generateToken(claims: Record<string, unknown> = {}): Promise<string> {
    // Strip registered claims that are controlled by signing options to avoid conflicts
    // jsonwebtoken will throw if both payload and options specify the same registered claim
    const payload: Record<string, unknown> = { ...claims, ...this.config.additionalClaims };
    delete payload.exp;
    delete payload.iat;
    delete payload.nbf;
    delete payload.iss;
    delete payload.aud;

    const options = {
      expiresIn: this.config.expiresIn,
      issuer: this.config.issuer,
      audience: this.config.audience
    };

    try {
      return sign(payload, this.config.secretKey, options);
    } catch (error) {
      throw RotationError.apiError('Failed to generate token', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
}

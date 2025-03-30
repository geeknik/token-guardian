import { DefaultRotator } from './services/DefaultRotator';
import { RotationResult } from '../interfaces/RotationResult';
import { Logger } from '../utils/Logger';
import { RotationStrategy } from './RotationStrategy';

/**
 * Manages token rotation using different rotation strategies
 */
export class TokenRotator {
  private readonly logger: Logger;
  private readonly rotators: Map<string, RotationStrategy>;

  constructor() {
    this.logger = new Logger('info');
    this.rotators = new Map();
    this.initializeRotators();
  }

  /**
   * Initialize default rotators
   */
  private initializeRotators(): void {
    this.rotators.set('default', new DefaultRotator({
      secretKey: process.env.TOKEN_GUARDIAN_SECRET_KEY || 'default-secret-key',
      expiresIn: 3600,
      issuer: 'token-guardian',
      audience: 'default',
      validationOptions: {
        verifyExpiration: true,
        verifyIssuer: true,
        verifyAudience: true,
        clockTolerance: 0
      }
    }));
  }

  /**
   * Register a custom rotator
   */
  public registerRotator(name: string, rotator: RotationStrategy): void {
    this.rotators.set(name, rotator);
    this.logger.info(`Registered rotator: ${name}`);
  }

  /**
   * Get a registered rotator
   */
  public getRotator(name: string = 'default'): RotationStrategy {
    const rotator = this.rotators.get(name);
    if (!rotator) {
      throw new Error(`Rotator not found: ${name}`);
    }
    return rotator;
  }

  /**
   * Rotate a token using the specified rotator
   */
  public async rotateToken(token: string): Promise<RotationResult> {
    const rotator = this.getRotator('default');
    return rotator.rotateToken(token);
  }
}

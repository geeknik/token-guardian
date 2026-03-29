import { DefaultRotator } from './services/DefaultRotator';
import { RotationResult } from '../interfaces/RotationResult';
import { Logger } from '../utils/Logger';
import { RotationStrategy } from './RotationStrategy';
import { ServiceRotator } from './ServiceRotator';
import { AWSRotator } from './services/AWSRotator';
import { GitHubRotator } from './services/GitHubRotator';

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
    const secretKey = process.env.TOKEN_GUARDIAN_SECRET_KEY;

    if (secretKey) {
      this.rotators.set('default', new DefaultRotator({
        secretKey,
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
    } else {
      this.logger.warn('Default JWT rotator disabled because TOKEN_GUARDIAN_SECRET_KEY is not set');
    }

    this.rotators.set('aws', this.wrapServiceRotator(new AWSRotator(), 'aws-token'));
    this.rotators.set('github', this.wrapServiceRotator(new GitHubRotator(), 'github-token'));
  }

  /**
   * Adapt a service rotator to the shared rotation strategy interface.
   */
  private wrapServiceRotator(rotator: ServiceRotator, defaultTokenName: string): RotationStrategy {
    return {
      rotateToken: (currentToken: string, tokenName?: string) =>
        rotator.rotateToken(tokenName || defaultTokenName, currentToken)
    };
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
  public async rotateToken(
    token: string,
    rotatorName: string = 'default',
    tokenName?: string
  ): Promise<RotationResult> {
    const rotator = this.getRotator(rotatorName);
    return rotator.rotateToken(token, tokenName);
  }
}

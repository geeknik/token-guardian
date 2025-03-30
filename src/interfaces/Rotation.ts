import { RotationResult } from './RotationResult';

/**
 * Rotation strategy types
 */
export enum RotationStrategyType {
  Default = 'default',
  GitHub = 'github',
  AWS = 'aws'
}

/**
 * Base interface for token rotation strategies
 */
export interface RotationStrategy {
  rotateToken(tokenName: string, currentToken: string): Promise<RotationResult>;
  validateToken(token: string): Promise<boolean>;
  isTokenExpired(token: string): boolean;
} 
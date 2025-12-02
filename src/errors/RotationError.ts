/**
 * Custom error class for token rotation errors
 */
export class RotationError extends Error {
  constructor(
    message: string,
    public readonly code: string = 'ROTATION_ERROR',
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'RotationError';
    
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, RotationError.prototype);
  }

  /**
   * Create a RotationError for validation failures
   */
  static validationError(message: string, details?: Record<string, unknown>): RotationError {
    return new RotationError(message, 'VALIDATION_ERROR', details);
  }

  /**
   * Create a RotationError for API errors
   */
  static apiError(message: string, details?: Record<string, unknown>): RotationError {
    return new RotationError(message, 'API_ERROR', details);
  }

  /**
   * Create a RotationError for configuration errors
   */
  static configError(message: string, details?: Record<string, unknown>): RotationError {
    return new RotationError(message, 'CONFIG_ERROR', details);
  }
} 

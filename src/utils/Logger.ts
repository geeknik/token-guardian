import winston from 'winston';

/**
 * Logger for TokenGuardian
 */
export class Logger {
  private logger: winston.Logger;

  /**
   * Creates a new Logger
   * @param level Log level
   */
  constructor(level: string = 'info') {
    this.logger = winston.createLogger({
      level,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ level, message, timestamp }) => {
          return `${timestamp} [TokenGuardian] ${level.toUpperCase()}: ${message}`;
        })
      ),
      transports: [
        new winston.transports.Console()
      ]
    });
  }

  /**
   * Logs a debug message
   * @param message The message to log
   * @param meta Optional metadata
   */
  public debug(message: string, meta?: any): void {
    this.logger.debug(message, meta);
  }

  /**
   * Logs an info message
   * @param message The message to log
   * @param meta Optional metadata
   */
  public info(message: string, meta?: any): void {
    this.logger.info(message, meta);
  }

  /**
   * Logs a warning message
   * @param message The message to log
   * @param meta Optional metadata
   */
  public warn(message: string, meta?: any): void {
    this.logger.warn(message, meta);
  }

  /**
   * Logs an error message
   * @param message The message to log
   * @param meta Optional metadata
   */
  public error(message: string, meta?: any): void {
    this.logger.error(message, meta);
  }
}

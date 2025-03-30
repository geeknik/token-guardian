import axios from 'axios';
import { ServiceRotator } from '../ServiceRotator';
import { RotationResult } from '../../interfaces/RotationResult';

/**
 * Rotator for GitHub tokens
 */
export class GitHubRotator implements ServiceRotator {
  /**
   * Rotates a GitHub token by creating a new one and deleting the old one
   * @param tokenName The name/identifier of the token
   * @param currentToken The current token value
   * @returns Result of the rotation
   */
  public async rotateToken(tokenName: string, currentToken: string): Promise<RotationResult> {
    try {
      // Step 1: Validate the current token and gather its scope information
      let tokenScopes: string[] = [];
      let username: string = '';
      
      try {
        const response = await axios.get('https://api.github.com/user', {
          headers: {
            Authorization: `token ${currentToken}`,
            Accept: 'application/vnd.github.v3+json'
          }
        });
        
        // Extract scopes from response headers
        const scopeHeader = response.headers['x-oauth-scopes'] as string;
        tokenScopes = scopeHeader ? scopeHeader.split(', ') : [];
        username = response.data.login;
      } catch (error) {
        if (axios.isAxiosError(error) && error.response) {
          if (error.response.status === 401) {
            return {
              success: false,
              message: 'Current GitHub token is invalid or expired',
              newExpiry: null
            };
          }
        }
        throw error; // Re-throw for the outer catch block
      }
      
      if (!tokenScopes.length) {
        return {
          success: false,
          message: 'Could not determine token scopes for rotation',
          newExpiry: null
        };
      }
      
      // Step 2: Create a new token with the same scopes via GitHub API
      const _scopeString = tokenScopes.join(',');
      const note = `TokenGuardian Rotated Token (${new Date().toISOString()})`;
      
      const createTokenResponse = await axios.post(
        'https://api.github.com/authorizations',
        {
          scopes: tokenScopes,
          note,
          fingerprint: `token-guardian-${Date.now()}`
        },
        {
          headers: {
            Authorization: `token ${currentToken}`,
            Accept: 'application/vnd.github.v3+json'
          },
          auth: {
            username,
            password: '' // This will trigger a 2FA flow in production
                        // In a real world scenario, we'd need to handle 2FA
                        // or use a GitHub App installation token flow instead
          }
        }
      );
      
      const newToken = createTokenResponse.data.token;
      const tokenId = createTokenResponse.data.id;
      
      // If we got this far, we have a new token
      // Step 3: Verify the new token works
      try {
        await axios.get('https://api.github.com/user', {
          headers: {
            Authorization: `token ${newToken}`,
            Accept: 'application/vnd.github.v3+json'
          }
        });
      } catch (error) {
        return {
          success: false,
          message: 'New token validation failed - rotation aborted',
          newExpiry: null
        };
      }
      
      // Step 4: Schedule deletion of the old token
      // (For safety, this would be safer with a delay, but we'll do it immediately for demo)
      try {
        await axios.delete(`https://api.github.com/authorizations/${tokenId}`, {
          headers: {
            Authorization: `token ${currentToken}`,
            Accept: 'application/vnd.github.v3+json'
          }
        });
      } catch (error) {
        // We still return success because we have a new working token
        // But we log the error for cleanup
        console.error('Failed to delete old token:', error);
      }
      
      // Step 5: Return successful rotation result
      // GitHub tokens don't have an expiry by default
      return {
        success: true,
        message: 'GitHub token rotated successfully',
        newToken,
        newExpiry: null 
      };
    } catch (error) {
      // Catch-all error handler for unexpected issues
      let errorMessage = 'Unknown error during GitHub token rotation';
      
      if (axios.isAxiosError(error)) {
        if (error.response) {
          errorMessage = `GitHub API error: ${error.response.status} - ${error.response.data?.message || 'Unknown error'}`;
        } else if (error.request) {
          errorMessage = 'No response received from GitHub API';
        } else {
          errorMessage = `Error setting up request: ${error.message}`;
        }
      } else if (error instanceof Error) {
        errorMessage = `Error rotating GitHub token: ${error.message}`;
      }
      
      return {
        success: false,
        message: errorMessage,
        newExpiry: null
      };
    }
  }
}

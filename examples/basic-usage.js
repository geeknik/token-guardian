/**
 * TokenGuardian Basic Usage Example
 * 
 * This example demonstrates the basic functionality of TokenGuardian,
 * including token detection, protection, rotation, and canary features.
 */

const { TokenGuardian } = require('token-guardian');

// Initialize TokenGuardian with custom config
const guardian = new TokenGuardian({
  services: ['github', 'aws'],
  rotationInterval: '7d',
  canaryEnabled: true,
  logLevel: 'debug'
});

// Example 1: Scan a string for potential tokens/secrets
console.log('Example 1: Scanning for secrets');
const testString = `
This string contains some secrets:
- AWS Key: AKIAIOSFODNN7EXAMPLE
- GitHub Token: ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9
- Some normal text that's not a secret
`;

const scanResult = guardian.scanString(testString);
console.log('Scan found secrets:', scanResult.found);
console.log('Detected secrets:');
scanResult.matches.forEach(match => {
  console.log(`- ${match.type} (Confidence: ${Math.round(match.confidence * 100)}%)`);
});
console.log('Input entropy:', scanResult.entropy);
console.log('-'.repeat(50));

// Example 2: Protect a GitHub token with rotation and canary
console.log('Example 2: Protecting tokens');
const githubToken = 'ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9'; // example token
guardian.protect('GITHUB_TOKEN', githubToken, {
  rotationEnabled: true,
  canaryEnabled: true,
  serviceType: 'github'
});
console.log('GitHub token protected successfully');

// Example 3: Protect AWS credentials
const awsCredentials = 'AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'; // format: accessKeyId:secretAccessKey
guardian.protect('AWS_CREDENTIALS', awsCredentials, {
  rotationEnabled: true,
  canaryEnabled: true,
  serviceType: 'aws'
});
console.log('AWS credentials protected successfully');
console.log('-'.repeat(50));

// Example 4: Retrieve a protected token
console.log('Example 4: Retrieving protected tokens');
const retrievedToken = guardian.getToken('GITHUB_TOKEN');
console.log('Retrieved token:', retrievedToken.substring(0, 10) + '...');
console.log('-'.repeat(50));

// Example 5: List all protected tokens
console.log('Example 5: Listing protected tokens');
const tokenList = guardian.listTokens();
console.log('Protected tokens:', tokenList);
console.log('-'.repeat(50));

// Example 6: Get audit log
console.log('Example 6: Retrieving audit log');
const auditLog = guardian.getAuditLog();
console.log(`Audit log entries: ${auditLog.length}`);
auditLog.forEach(entry => {
  console.log(`- ${entry.timestamp}: ${entry.action.toUpperCase()} ${entry.tokenName}`);
});
console.log('-'.repeat(50));

// Example 7: Token Rotation (This would be async in real usage)
console.log('Example 7: Manual token rotation');
console.log('To rotate a token, use:');
console.log(`
async function rotateMyToken() {
  const result = await guardian.rotateToken('AWS_CREDENTIALS');
  console.log('Rotation successful:', result.success);
  console.log('New token:', result.newToken?.substring(0, 10) + '...');
}
`);
console.log('-'.repeat(50));

// Example 8: Install Git hooks to prevent committing secrets
console.log('Example 8: Installing Git hooks');
console.log('To install pre-commit hooks, use:');
console.log(`
const installed = guardian.installGitHooks();
console.log('Git hooks installed successfully:', installed);
`);

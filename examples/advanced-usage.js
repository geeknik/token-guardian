/**
 * TokenGuardian Advanced Usage Example
 * 
 * This example demonstrates how to integrate TokenGuardian into a production application
 * with real token rotation, monitoring, and system integration.
 */

// Import required packages
const { TokenGuardian } = require('token-guardian');
const express = require('express'); // You would need to install this
const cron = require('node-cron');  // You would need to install this

// Create an express app for our monitoring API
const app = express();
const PORT = process.env.PORT || 3000;

// Initialize TokenGuardian with production config
const guardian = new TokenGuardian({
  services: ['github', 'aws', 'stripe'],
  rotationInterval: '30d', // 30 days default
  canaryEnabled: true,
  encryptionKey: process.env.GUARDIAN_ENCRYPTION_KEY,
  logLevel: process.env.NODE_ENV === 'production' ? 'info' : 'debug'
});

// Initialize our credential store with actual API keys
async function initializeCredentials() {
  console.log('Initializing token storage...');
  
  // GitHub token (with organization-wide access)
  if (process.env.GITHUB_TOKEN) {
    guardian.protect('GITHUB_ORG_TOKEN', process.env.GITHUB_TOKEN, {
      rotationEnabled: true,
      rotationInterval: '90d', // GitHub tokens last longer
      canaryEnabled: true,
      serviceType: 'github'
    });
    console.log('GitHub token protected');
  }
  
  // AWS credentials
  if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
    const awsCreds = `${process.env.AWS_ACCESS_KEY_ID}:${process.env.AWS_SECRET_ACCESS_KEY}`;
    guardian.protect('AWS_API_CREDENTIALS', awsCreds, {
      rotationEnabled: true,
      rotationInterval: '30d',
      canaryEnabled: true,
      serviceType: 'aws'
    });
    console.log('AWS credentials protected');
  }
  
  // Stripe API key
  if (process.env.STRIPE_API_KEY) {
    guardian.protect('STRIPE_API_KEY', process.env.STRIPE_API_KEY, {
      rotationEnabled: true, 
      rotationInterval: '60d',
      canaryEnabled: true,
      serviceType: 'default' // Custom rotator not implemented yet
    });
    console.log('Stripe API key protected');
  }
  
  // Database connection string - not rotated but still protected
  if (process.env.DATABASE_URL) {
    guardian.protect('DATABASE_URL', process.env.DATABASE_URL, {
      rotationEnabled: false,
      canaryEnabled: true,
      serviceType: 'default'
    });
    console.log('Database connection string protected');
  }
  
  console.log('All credentials initialized and protected');
}

// Function to get token for API requests
function getCredential(name) {
  return guardian.getToken(name);
}

// Set up monitoring endpoint
app.get('/api/system/credential-status', (req, res) => {
  const tokens = guardian.listTokens();
  const status = tokens.map(tokenName => {
    const data = guardian.getTokenData(tokenName);
    if (!data) return null;
    
    return {
      name: tokenName,
      service: data.config.serviceType,
      lastUsed: data.lastUsed,
      rotationEnabled: data.config.rotationEnabled,
      nextRotation: data.config.rotationEnabled 
        ? calculateNextRotation(data.created, data.config.rotationInterval)
        : null
    };
  }).filter(Boolean);
  
  res.json({ status });
});

// Schedule token rotation using cron
function setupTokenRotation() {
  // Check daily at midnight if any tokens need rotation
  cron.schedule('0 0 * * *', async () => {
    console.log('Running scheduled token rotation check...');
    const tokens = guardian.listTokens();
    
    for (const tokenName of tokens) {
      const data = guardian.getTokenData(tokenName);
      if (!data || !data.config.rotationEnabled) continue;
      
      const nextRotation = calculateNextRotation(data.created, data.config.rotationInterval);
      const now = new Date();
      
      // If rotation is due
      if (nextRotation <= now) {
        try {
          console.log(`Rotating token: ${tokenName}`);
          const result = await guardian.rotateToken(tokenName);
          
          if (result.success) {
            console.log(`Token ${tokenName} rotated successfully`);
            
            // Update environment variables if needed
            if (tokenName === 'AWS_API_CREDENTIALS') {
              const [accessKey, secretKey] = result.newToken.split(':');
              process.env.AWS_ACCESS_KEY_ID = accessKey;
              process.env.AWS_SECRET_ACCESS_KEY = secretKey;
            } else if (tokenName === 'GITHUB_ORG_TOKEN') {
              process.env.GITHUB_TOKEN = result.newToken;
            } else if (tokenName === 'STRIPE_API_KEY') {
              process.env.STRIPE_API_KEY = result.newToken;
            }
          } else {
            console.error(`Failed to rotate token ${tokenName}: ${result.message}`);
            // Send alert to admin
            sendAlertToAdmin(`Token rotation failed: ${tokenName}`, result.message);
          }
        } catch (error) {
          console.error(`Error during token rotation for ${tokenName}:`, error);
          sendAlertToAdmin(`Token rotation error: ${tokenName}`, error.message);
        }
      }
    }
  });
  
  console.log('Token rotation scheduler configured');
}

// Helper to calculate next rotation date
function calculateNextRotation(createdDate, interval) {
  const created = new Date(createdDate);
  const unit = interval.slice(-1);
  const value = parseInt(interval.slice(0, -1), 10);
  
  switch (unit) {
    case 'd':
      return new Date(created.setDate(created.getDate() + value));
    case 'h':
      return new Date(created.setHours(created.getHours() + value));
    case 'm':
      return new Date(created.setMinutes(created.getMinutes() + value));
    default:
      return new Date(created.setDate(created.getDate() + 30)); // Default: 30 days
  }
}

// Mock function to send alerts to administrators
function sendAlertToAdmin(subject, message) {
  console.error(`ALERT: ${subject}`, message);
  // In a real app, this would send an email, Slack message, etc.
}

// Set up canary token monitoring
function setupCanaryMonitoring() {
  // This would typically hook into your monitoring/logging system
  guardian.canaryService.onCanaryTriggered((tokenName, context) => {
    console.error(`SECURITY ALERT: Canary token triggered for ${tokenName}`);
    console.error('Context:', context);
    
    // Send high-priority alert
    sendAlertToAdmin(
      `SECURITY BREACH: Token ${tokenName} has been leaked`, 
      `The token was used outside of authorized systems at ${new Date().toISOString()}`
    );
    
    // In a real system, you might want to automatically:
    // 1. Rotate the compromised token immediately
    // 2. Restrict permissions temporarily
    // 3. Log IP and other context for forensic analysis
  });
}

// Start the application
async function startApp() {
  try {
    // Initialize token protection
    await initializeCredentials();
    
    // Set up scheduled rotation
    setupTokenRotation();
    
    // Set up canary monitoring
    setupCanaryMonitoring();
    
    // Install git hooks for local development
    if (process.env.NODE_ENV === 'development') {
      guardian.installGitHooks();
    }
    
    // Start Express server
    app.listen(PORT, () => {
      console.log(`Token management system running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start application:', error);
    process.exit(1);
  }
}

// Run the application
startApp();

// Export helper for other modules to use
module.exports = {
  getCredential
};

# Publishing to npm

This document describes how to publish the TokenGuardian package to the npm registry using GitHub Actions.

## Prerequisites

1. You need to have an npm account with publishing rights for this package.
2. Generate an npm access token with publishing permissions.
3. Set up GitHub secrets with your npm token.

## Generating an npm token

1. Log in to your npm account on https://www.npmjs.com/
2. Go to your profile settings
3. Select "Access Tokens"
4. Click "Generate New Token"
5. Select "Automation" token type
6. Set the appropriate permissions (needs "Read and write" access)
7. Generate and copy the token

## Setting up GitHub Secrets

1. Navigate to your GitHub repository
2. Go to "Settings" > "Secrets and variables" > "Actions"
3. Click "New repository secret"
4. Create a secret named `NPM_TOKEN` with the value of your npm token
5. Click "Add secret"

## Using GitHub Workflows

### Manual workflow setup

Since GitHub Actions workflows need to be in the `.github/workflows` directory, you'll need to:

1. Create a `.github/workflows` directory in your repository
2. Copy the workflow files to that directory:

```bash
mkdir -p .github/workflows
cp ci-workflow.yml .github/workflows/ci.yml
cp release-workflow.yml .github/workflows/release.yml
```

### Automatic publishing via GitHub Release

To publish a new version of the package:

1. Update the version in `package.json`
2. Create and push a new tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. Or create a new release through the GitHub UI:
   - Go to "Releases" in your repository
   - Click "Draft a new release"
   - Enter the tag version (e.g., `v0.1.0`)
   - Fill in the release title and description
   - Click "Publish release"

The release workflow will automatically:
- Check out the tagged code
- Install dependencies
- Run tests
- Build the package
- Publish to npm

## Manual Publishing

If you prefer to publish manually:

```bash
# Login to npm
npm login

# Build the package
npm run build

# Publish
npm publish
```

## Versioning

Follow Semantic Versioning (SemVer) for version numbers:
- MAJOR version for incompatible API changes
- MINOR version for backwards-compatible functionality
- PATCH version for backwards-compatible bug fixes

Use npm version to update the package version:

```bash
# For a patch release
npm version patch

# For a minor release
npm version minor

# For a major release
npm version major
```

This will update `package.json`, create a new commit, and create a new tag.

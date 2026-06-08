# GitHub Actions Setup for Multi-Architecture Docker Builds

## Overview
This GitHub Actions workflow automatically builds and pushes your Docker image to Docker Hub for both `amd64` and `arm64` architectures whenever you push to the `main` branch or create a release tag.

## Prerequisites

### 1. Docker Hub Account & Access Token
You need a Docker Hub account and a personal access token (PAT):

1. Go to [Docker Hub](https://hub.docker.com) and log in
2. Click your profile icon → **Account Settings** → **Security** → **New Access Token**
3. Create a token with "Read & Write" permissions
4. Copy the token (you won't be able to see it again)

### 2. GitHub Repository Secrets
Add these secrets to your GitHub repository:

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Create two new secrets:
   - `DOCKERHUB_USERNAME`: Your Docker Hub username
   - `DOCKERHUB_TOKEN`: Your personal access token from Docker Hub

## How It Works

The workflow (`.github/workflows/docker-build.yml`) will:

- **Trigger on**:
  - Push to `main` branch → builds and tags as `main`, `sha-{commit}`, and `latest`
  - Push to version tags (e.g., `v1.2.3`) → builds and tags with the version
  - Manual trigger via GitHub Actions UI

- **Builds for**: `linux/amd64` and `linux/arm64` (both 64-bit architectures)

- **Caches**: Uses GitHub Actions cache to speed up subsequent builds

## Usage

### Automatic Builds
Just push to `main` or tag a release:
```bash
git push origin main
# or
git tag v1.2.3
git push origin v1.2.3
```

Your images will be available at:
- `yourusername/prestoback:latest` (from main)
- `yourusername/prestoback:main` (from main branch)
- `yourusername/prestoback:v1.2.3` (from tag)
- `yourusername/prestoback:v1.2` (from tag, short version)

### Manual Trigger
1. Go to **Actions** → **Build and Push Docker Image**
2. Click **Run workflow** → select branch → **Run workflow**

## Dockerfile Notes

Your multi-stage Dockerfile works perfectly for this:
- **Stage 1**: Builds the Go binary with `CGO_ENABLED=0` (static binary)
- **Stage 2**: Creates a minimal Alpine image with only runtime dependencies

The `linux/arm64` build will work correctly because:
- Go is built with `-os=linux` (architecture-independent at compile time)
- Alpine has arm64 support
- No native dependencies (CGO disabled)

## Troubleshooting

**Build fails with "not authorized":**
- Check that `DOCKERHUB_TOKEN` is set correctly
- Verify the token hasn't expired
- Ensure token has "Read & Write" permissions

**ARM64 build is slow:**
- This is normal for cross-architecture builds on GitHub Actions
- Consider enabling self-hosted ARM64 runners for faster builds (advanced)

**Want to change the image name?**
- Edit `.github/workflows/docker-build.yml`
- Change the `IMAGE_NAME` line to your desired name
- The username is pulled from the secret, so only change the suffix

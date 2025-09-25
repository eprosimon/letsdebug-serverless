# Deployment Guide

This guide explains how to deploy the Let's Debug web application to Vercel.

## Prerequisites

- A Vercel account
- The repository connected to Vercel
- Go 1.24+ support enabled

## Deployment Steps

### 1. Connect Repository to Vercel

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Click "New Project"
3. Import your repository
4. Select the `web` folder as the root directory

### 2. Configure Build Settings

The following settings should be automatically detected:

- **Framework Preset**: Next.js
- **Root Directory**: `web`
- **Build Command**: `pnpm build && pnpm build:api`
- **Output Directory**: `.next`
- **Install Command**: `pnpm install`

### 3. Environment Variables

No environment variables are required for basic functionality.

### 4. Go Runtime Configuration

The `vercel.json` file is already configured to:

- Use Go 1.x runtime for the API functions
- Route `/api/debug` requests to the Go handler
- Build both Next.js and Go components

### 5. Deploy

1. Click "Deploy" in the Vercel dashboard
2. Wait for the build to complete
3. Your app will be available at the provided Vercel URL

## API Endpoints

After deployment, the following endpoints will be available:

- **Frontend**: `https://your-app.vercel.app/`
- **API**: `https://your-app.vercel.app/api/debug`

## Testing the Deployment

1. Visit your deployed URL
2. Enter a domain (e.g., `example.com`)
3. Select a validation method
4. Click "Debug Domain"
5. Verify the results are displayed correctly

## Troubleshooting

### Build Failures

- Ensure Go 1.24+ is available in the build environment
- Check that all dependencies are properly installed
- Verify the `go.mod` file in the `api` directory

### API Issues

- Check Vercel function logs for Go runtime errors
- Verify the API endpoint is accessible
- Test with a simple domain first

### Frontend Issues

- Check browser console for JavaScript errors
- Verify all UI components are properly imported
- Test responsive design on mobile devices

## Custom Domain

To use a custom domain:

1. Go to your project settings in Vercel
2. Navigate to "Domains"
3. Add your custom domain
4. Configure DNS records as instructed

## Performance Optimization

- The app uses Next.js static generation for optimal performance
- Go API functions are serverless and scale automatically
- Images and assets are optimized by Vercel's CDN

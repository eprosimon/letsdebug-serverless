# Let's Debug Web App

A Next.js web application that provides a user-friendly interface for the Let's Debug serverless library. This app allows users to diagnose Let's Encrypt certificate issuance issues for their domains.

## Features

- **Mobile-first responsive design** with Tailwind CSS
- **Query string support** for shareable URLs with domain and validation method
- **Real-time domain debugging** using the Go letsdebug-serverless package
- **Multiple validation methods** (HTTP-01, DNS-01, TLS-ALPN-01)
- **Categorized results** by severity (Fatal, Error, Warning, Debug)
- **Shareable URLs** for easy collaboration

## Tech Stack

- **Frontend**: Next.js 15, React 19, TypeScript
- **Styling**: Tailwind CSS, shadcn/ui components
- **Backend**: Go API routes using letsdebug-serverless package
- **Deployment**: Vercel with Go runtime support

## Getting Started

### Prerequisites

- Node.js 18+ and pnpm
- Go 1.24+

### Development

1. Install dependencies:

   ```bash
   pnpm install
   ```

2. Run the development server:

   ```bash
   pnpm dev
   ```

3. Open [http://localhost:3000](http://localhost:3000) in your browser.

### API Usage

The app includes a Go API endpoint at `/api/debug` that accepts POST requests:

```json
{
  "domain": "example.com",
  "method": "http-01"
}
```

Response:

```json
{
  "problems": [
    {
      "name": "ProblemName",
      "explanation": "Human readable explanation",
      "detail": "Technical details",
      "severity": "Error"
    }
  ],
  "error": "Optional error message"
}
```

## Deployment

This app is configured for Vercel deployment with Go runtime support:

1. Connect your repository to Vercel
2. The app will automatically deploy with the Go API functions
3. The `vercel.json` configuration handles routing to Go functions

## URL Structure

The app supports query string parameters for shareable URLs:

- `?domain=example.com` - Sets the domain to debug
- `?method=http-01` - Sets the validation method (http-01, dns-01, tls-alpn-01)

Example: `https://your-app.vercel.app?domain=example.com&method=dns-01`

## Components

- **Main Page**: Domain input form with validation method selection
- **Results Display**: Categorized problem display with severity indicators
- **Toast Notifications**: User feedback for actions and errors
- **Responsive Design**: Mobile-first approach with desktop optimization

## Contributing

1. Follow the existing code style and patterns
2. Ensure mobile-first responsive design
3. Add proper TypeScript types
4. Test with various domains and validation methods

# Let's Debug Serverless

A serverless adaptation of the [Let's Debug](https://github.com/letsdebug/letsdebug) library, designed to run on Vercel serverless functions with public DNS resolution instead of libunbound.

## Overview

This project provides a serverless-compatible version of the Let's Debug diagnostic tool for Let's Encrypt certificate issuance issues. The main adaptation involves replacing the libunbound dependency with public DNS resolution to ensure compatibility with serverless environments.

## Key Differences from Original

- **DNS Resolution**: Uses public DNS servers instead of libunbound for DNS lookups
- **Serverless-First**: Designed specifically for Vercel serverless functions
- **No Fluid Compute**: Only supports Vercel's serverless compute model
- **Simplified Dependencies**: Removes system-level dependencies that aren't available in serverless environments

## Limitations

- **Public DNS Only**: Uses public DNS servers instead of libunbound
- **Vercel Only**: Designed specifically for Vercel serverless functions
- **No Fluid Compute**: Does not support Vercel's fluid compute model
- **Network Dependencies**: Requires internet access for DNS resolution

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Development Guidelines

- Follow Go best practices and conventions
- Add tests for new functionality
- Update documentation for API changes
- Ensure serverless compatibility
- Test with Vercel functions

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Based on the original [Let's Debug](https://github.com/letsdebug/letsdebug) project
- Adapted for serverless environments with public DNS resolution
- Designed for Vercel serverless functions

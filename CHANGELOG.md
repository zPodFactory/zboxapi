# Changelog

All notable changes to the zboxapi project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.7] - 2025-07-07

### Added
- **VLAN Management API**: Complete VLAN interface management system
  - Create, read, update, and delete VLAN interfaces via API
  - Automatic network configuration management
  - System VLAN protection (default: 10,20,30 and zPod: 64,128,192)
  - Network overlap detection and validation
  - Individual configuration files in `/etc/network/interfaces.d/`
  - Enable/disable VLAN interfaces via API

### Changed
- **Documentation Updates**:
  - Updated README.md with accurate configuration format and authentication details

### Fixed
- **Code Quality**:
  - Replaced deprecated `List` type annotations with built-in `list`
  - Added proper exception chaining with `from e` syntax
  - Removed unused imports (`os`, `IO`)
- **Exception Handling**: Fixed all exception handling to use proper chaining
- **Type Annotations**: Updated to use modern Python type annotations (Python 3.9+)

### Removed
- **Unused Imports**: Cleaned up unused `os` and `IO` imports

## [0.0.6] - 2024-05-22

### Added
- **DNS Management API**: Complete DNS record management system
  - Create, read, update, and delete DNS records in `/etc/hosts`
  - Automatic dnsmasq integration with SIGHUP reloading
  - File locking for concurrent access safety
  - RFC 1123 compliant hostname validation
  - IPv4 address validation
- **Authentication System**: API key authentication using zPod password
- **Configuration Management**: Support for `/etc/zboxapi.conf` configuration file
- **Systemd Service**: Complete systemd service integration
- **Comprehensive Documentation**: Complete API documentation with examples

### Technical Details
- **File Management**: Thread-safe operations with file locking
- **Error Handling**: Comprehensive HTTP status codes and error messages
- **Validation**: Strict input validation for all API endpoints
- **Integration**: Seamless dnsmasq integration for immediate DNS updates

---

## Version History

- **0.0.6**: Initial release with DNS management functionality
- **0.0.7**: Added VLAN management, improved DNS validation, and code quality fixes

## Contributing

When adding new entries to this changelog, please follow the existing format and include:
- Clear, descriptive change messages
- Categorization (Added, Changed, Fixed, Removed, etc.)
- Technical details where relevant
- Breaking changes clearly marked
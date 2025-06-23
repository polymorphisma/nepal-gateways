## [0.2.0] - 2025/06/23
### Added
- Support for Khalti payment gateway (ePayment v2 API).
  - Includes `KhaltiClient` for payment initiation and lookup-based verification.
  - Comprehensive unit tests for `KhaltiClient`.
- Documentation (`docs/KhaltiClient.md`) for Khalti integration.

### Changed
- Updated main `README.md` to include Khalti support and examples.
- Updated package `__init__.py` to export `KhaltiClient`.
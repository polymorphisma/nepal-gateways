# Contributing to Nepal Gateways

First off, thank you for considering contributing to `nepal-gateways`! We welcome contributions from everyone. Whether it's reporting a bug, proposing a new feature, improving documentation, or writing code, your help is appreciated.

This document provides guidelines for contributing to this project.

## Table of Contents

-   [Code of Conduct](#code-of-conduct)
-   [How Can I Contribute?](#how-can-i-contribute)
    -   [Reporting Bugs](#reporting-bugs)
    -   [Suggesting Enhancements or New Gateways](#suggesting-enhancements-or-new-gateways)
    -   [Your First Code Contribution](#your-first-code-contribution)
    -   [Pull Requests](#pull-requests)
-   [Development Setup](#development-setup)
-   [Coding Standards](#coding-standards)
-   [Testing](#testing)
-   [Documentation](#documentation)
-   [Releasing (For Maintainers)](#releasing-for-maintainers)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [your-email@example.com or project maintainer contact].
*(You'll need to create a `CODE_OF_CONDUCT.md` file. The Contributor Covenant is a good template: [https://www.contributor-covenant.org/](https://www.contributor-covenant.org/))*

## How Can I Contribute?

### Reporting Bugs

If you encounter a bug, please help us by submitting an issue to our [GitHub Issues page](https://github.com/yourusername/nepal-gateways/issues). <!-- Replace with your actual repo URL -->

When reporting a bug, please include:

1.  **A clear and descriptive title.**
2.  **Steps to reproduce the bug:** Provide as much detail as possible.
3.  **What you expected to happen.**
4.  **What actually happened:** Include any error messages and full tracebacks.
5.  **Your environment:**
    *   Python version (e.g., 3.10).
    *   `nepal-gateways` package version.
    *   Operating System.
    *   Relevant gateway and mode (e.g., "eSewa sandbox").

### Suggesting Enhancements or New Gateways

We love to hear your ideas for improving `nepal-gateways` or adding support for new Nepali payment gateways!

1.  **Check existing issues:** See if your suggestion has already been discussed.
2.  **Open a new issue:** Clearly describe the enhancement or the new gateway you'd like to see supported.
    *   For enhancements, explain the use case and why it would be beneficial.
    *   For new gateways, please provide links to their official API documentation if available.

### Your First Code Contribution

Unsure where to begin? You can look for issues tagged `good first issue` or `help wanted`.
If you're planning to add a new gateway or a significant feature, it's a good idea to discuss it in an issue first to ensure it aligns with the project's goals.

### Pull Requests

We use Pull Requests (PRs) for code contributions.

1.  **Fork the repository** on GitHub.
2.  **Clone your fork locally:** `git clone https://github.com/polymorphisma/nepal-gateways.git`
3.  **Create a new branch** for your changes: `git checkout -b feature/your-feature-name` or `fix/bug-description`.
4.  **Set up your development environment** (see [Development Setup](#development-setup)).
5.  **Make your changes.** Ensure you adhere to the [Coding Standards](#coding-standards).
6.  **Write tests** for your changes (see [Testing](#testing)). All new features should have corresponding tests, and bug fixes should ideally include a test that reproduces the bug.
7.  **Ensure all tests pass:** `uv run pytest`
8.  **Update documentation** if your changes affect it.
9.  **Commit your changes** with clear and descriptive commit messages.
10. **Push your branch** to your fork on GitHub: `git push origin feature/your-feature-name`
11. **Open a Pull Request** from your branch to the `main` branch (or `develop` branch, if used) of the original `nepal-gateways` repository.
    *   Provide a clear title and description for your PR, explaining the changes and referencing any related issues.

## Development Setup

We use `uv` for project and environment management.

1.  **Clone your fork:**
    ```bash
    git clone https://github.com/polymorphisma/nepal-gateways.git
    cd nepal-gateways
    ```
2.  **Create and activate a virtual environment (recommended):**
    ```bash
    # Using uv to create and manage a virtual environment
    uv venv .venv # Creates a .venv in the current directory
    source .venv/bin/activate # On Linux/macOS
    # .venv\Scripts\activate # On Windows
    ```
3.  **Install dependencies, including development tools:**
    The project uses `pyproject.toml` to define dependencies.
    ```bash
    uv pip install -e ".[dev]"
    ```
    This installs the package in editable mode (`-e .`) along with the development dependencies specified in `[project.optional-dependencies].dev` in `pyproject.toml`.

4.  **Set up pre-commit hooks (Optional but Recommended):**
    ```bash
    # uv pip install pre-commit # If not already installed via dev dependencies
    # pre-commit install
    ```

## Coding Standards

*   **Style:** We generally follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) for Python code. We use `black` for code formatting and `ruff` for linting. Please format your code before committing.
    ```bash
    uv run black .
    uv run ruff check . --fix
    ```
*   **Type Hinting:** All new code should include type hints (PEP 484).
*   **Docstrings:** Use Google-style docstrings for modules, classes, and functions.
*   **Logging:** Use Python's standard `logging` module. Libraries should emit logs but not configure handlers (except a `NullHandler` at the package level). Get loggers via `logger = logging.getLogger(__name__)`.

## Testing

We use `pytest` for testing.

*   Tests are located in the `tests/` directory.
*   Ensure your changes are covered by tests.
*   Run tests locally before submitting a PR:
    ```bash
    uv run pytest
    ```
*   Aim for high test coverage. New features without tests will likely not be merged.

## Documentation

*   The main `README.md` provides an overview.
*   Gateway-specific documentation (like `docs/EsewaClient.md`) should be updated or created for any changes or new gateways.
*   Docstrings in the code are also a key part of the documentation.

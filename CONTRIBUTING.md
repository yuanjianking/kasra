# Contributing to Kasra

Thank you for your interest in contributing to **Kasra** — the AI Development Security Governance Platform.

We welcome contributions of all kinds, including bug reports, feature requests, documentation improvements, and code changes.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Reporting Issues](#reporting-issues)
- [Security Disclosures](#security-disclosures)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers.

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/your-username/kasra.git
   cd kasra
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- PostgreSQL (or use the Docker setup)

### Install dependencies

```bash
# Install the SDK in development mode
pip install -e ../kasra-sdk

# Install the app in development mode
pip install -e .

# Start services
docker compose up -d
```

### Run the server

```bash
uvicorn app.main:app --reload --port 8090
```

## Project Structure

```
kasra/
├── app/                    # FastAPI application
│   ├── main.py            # Application entry point
│   └── ...
├── config/                 # Configuration files
├── db/                     # Database migrations and seeds
├── deploy/                 # Deployment manifests
├── docs/                   # Documentation
├── frontend/               # React SPA dashboard
├── hooks/                  # Claude Code hook scripts
├── tests/                  # Test suite
└── skills/                 # Claude Code skills
```

## Pull Request Process

1. **Keep changes focused** — one feature or fix per PR.
2. **Write tests** for new functionality.
3. **Update documentation** if your change affects the API or user-facing behavior.
4. **Run tests** before submitting:
   ```bash
   python -m pytest tests/ -v
   ```
5. **Rebase** onto the latest `main` before submitting.
6. **Describe your changes** in the PR description — what problem it solves and how.
7. PRs require at least one review before merging.

## Coding Standards

- Follow [PEP 8](https://peps.python.org/pep-0008/) for Python code.
- Type hints are required for all function signatures.
- Use descriptive variable names and write docstrings for public APIs.
- For JavaScript/TypeScript in the frontend, follow the existing conventions.

### Commit messages

Use conventional commit format:

```
type(scope): brief description

feat:     New feature
fix:      Bug fix
docs:     Documentation only
style:    Formatting, no code change
refactor: Code restructuring
test:     Adding or fixing tests
chore:    Build/config changes
```

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_main.py -v

# Run with coverage
python -m pytest tests/ --cov=app --cov-report=term-missing
```

## Reporting Issues

When opening an issue, please include:

- A clear, descriptive title.
- Steps to reproduce (for bugs).
- Expected vs actual behavior.
- Environment details (OS, Python version, Docker version).
- Logs or screenshots where applicable.

## Security Disclosures

If you discover a security vulnerability, **do not** open a public issue. Please report it privately to the maintainers.

---

Thank you for helping make Kasra better!

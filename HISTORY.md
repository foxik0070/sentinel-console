# Changelog - Sentinel TUI Client Release

## [v2026.05.008] - Sentinel TUI Client & Initialization Scripts

This release introduces the official terminal user interface (TUI) for the Sentinel monitoring system, built on the `Textual` framework. It consists of two core scripts designed for high stability, secure authentication, and seamless OS integration.

### Added Files
* `sentinel_client.py` - The main interactive terminal dashboard and AI chat interface.
* `sentinel_client_init.py` - The automated installation, environment isolation, and configuration wizard.

### 🚀 Key Features & Architecture (`sentinel_client.py`)

* **Self-Bootstrapping Execution:**
  * Implemented an internal `os.execl()` bootstrap mechanism. If the script is launched using the system Python, it transparently intercepts the execution and restarts itself inside the dedicated virtual environment (`/opt/sentinel/venv/bin/python`). Eliminates the need for bash wrappers.
* **Session-Based LDAP Authentication:**
  * Transitioned from HTTP Basic Auth to a one-time `POST /login` session cookie mechanism via `httpx`. This prevents aggressive polling (every 2 seconds) from flooding the enterprise LDAP server and triggering Fail2Ban lockouts.
* **Anti-Ban Protection (Auto-Lock):**
  * Added safety circuit breakers that detect HTTP `401 Unauthorized` and `403 Banned` responses. If triggered (e.g., due to a changed password), the client immediately halts all background API polling to prevent extending the ban window, and displays a critical warning.
* **Bulletproof Vertical Layout:**
  * Abandoned CSS `Grid` and `Dock` layouts in favor of a strict `Vertical` stacking flow. This guarantees 100% UI stability without overlapping elements or vanishing headers, even when running inside terminal multiplexers like `tmux` or `screen`.
* **Dynamic UI Modes & Sorting:**
  * **Interactive Sorting (`s`):** Users can toggle the data grid between chronological order and a weighted severity order (`CRITICAL` > `WARNING`).
  * **View Toggling (`c`):** Users can switch between a Split-View (Grid + Chat) and a Full-Screen Chat View for reading extensive AI analysis logs.
* **Client-Side Metric Aggregation:**
  * Since the backend API (`/api/v1/issues`) provides a flat array, the client now dynamically calculates the counts for `AGENT`, `ROOT`, and `SECURITY` issues locally in real-time to populate the top status bar.
* **Safe Terminal Typography:**
  * Removed problematic emojis (like 🛡️) that caused black-box rendering artifacts due to cell-width miscalculations in certain SSH clients. Replaced them with high-contrast, VS Code-style rich text badges.

### 🛠️ Environment & Setup (`sentinel_client_init.py`)

* **PEP 668 Compliance:**
  * Designed to safely bypass modern OS restrictions (like "Externally Managed Environment" on Debian/Ubuntu/RHEL). The script automatically builds an isolated `venv` in `/opt/sentinel/venv`.
* **Automated Dependency Injection:**
  * Automatically provisions the virtual environment with `textual` and `httpx` via localized `pip` execution without modifying global OS packages.
* **Secure Configuration Wizard:**
  * Interactively prompts the administrator for the Sentinel API URL, LDAP Username, and Password.
  * Generates the configuration file at `/etc/sentinel/sentinel_client.conf`.
  * Enforces strict `0600` file permissions to ensure LDAP credentials remain readable only by the `root` user or the configuration owner.

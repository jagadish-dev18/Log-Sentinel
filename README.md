# Log Sentinel

A local-first authentication log analyzer for reviewing login activity, spotting repeated failures, and exporting an IP summary for follow-up investigation.

> **Important:** a flagged IP is an investigation signal, not proof of an attack. Review the surrounding events and your environment before taking action.

## Features

- Browser dashboard with event metrics, a failed-login timeline, and source-IP summaries
- Import a local `.log`, `.txt`, or `.csv` text file, or paste log lines
- Review recognized and unparsed records
- Configure the failed-login threshold
- Export an IP summary as CSV
- Python command-line analyzer for repeatable analysis and CSV reporting
- Sample authentication events for trying the project safely

## Project structure

```text
log-sentinel-modern/
├── analyzer/
│   ├── log_analyzer.py
│   └── tests/
│       └── test_log_analyzer.py
├── frontend/
│   ├── index.html
│   └── assets/
│       ├── css/
│       │   └── style.css
│       └── js/
│           └── app.js
├── samples/
│   └── sample_auth.log
├── scripts/
│   └── START_LOG_SENTINEL_WINDOWS.bat
├── .gitignore
└── README.md
```

## Run the web dashboard

### Option 1 — Windows

1. Install Python 3 if it is not already installed.
2. Double-click `scripts/START_LOG_SENTINEL_WINDOWS.bat`.
3. Open `http://127.0.0.1:8000` if your browser does not open automatically.
4. Select **Load sample data** or import your own authorized log file.

### Option 2 — any OS with Python 3

Run these commands from the project root:

```bash
python -m http.server 8000 --directory frontend
```

Then visit `http://127.0.0.1:8000`.

The web dashboard is static HTML, CSS, and JavaScript. Its browser-side analysis does not require a package installation or a build step.

## Run the Python analyzer

Use Python 3.10 or newer. From the project root:

```bash
python analyzer/log_analyzer.py samples/sample_auth.log --threshold 5 --csv ip_summary.csv
```

The command prints a summary and writes `ip_summary.csv` in the current directory. Choose a different path with `--csv`, for example `--csv reports/review.csv` (the destination directory must already exist).

Threshold values must be between 2 and 20.

## Run tests

From the project root:

```bash
python -m unittest discover -s analyzer/tests -v
```

The tests cover supported log patterns, unknown lines, and threshold-based review flags.

## Supported input patterns

- Key-value records, for example `2026-10-12 08:14:33 FAILED_LOGIN user=admin ip=192.0.2.44`
- Common OpenSSH authentication messages, such as `Failed password for ... from ...` and `Accepted password for ... from ...`
- JSON records containing an authentication-related `event`, `event_type`, `action`, or `status`

Unrecognized non-empty lines are counted and surfaced for review rather than silently treated as valid events. Exact timestamp and field support depends on the input format.

## Privacy and safe use

- The browser dashboard analyzes imported text locally; it does not upload logs to a server.
- Only analyze logs you are authorized to access. Logs can contain usernames, addresses, and other sensitive operational details; handle exports accordingly.
- The sample uses documentation-only IP ranges and is intended for demonstration.
- The project is not a live network monitor, SIEM replacement, or automated incident-response system.
- The parser uses a configurable count threshold. It does not establish intent, identify an attacker, or prove brute-force activity.

## Technology

- HTML, CSS, and vanilla JavaScript for the browser interface
- Python standard library for the command-line analyzer and unit tests

## Development notes

Keep browser presentation in `frontend/`, log parsing and reporting in `analyzer/`, reusable test cases in `analyzer/tests/`, and non-sensitive examples in `samples/`. Add dependencies only when there is a clear need and document their installation and security implications here.

## License

No license has been added yet. If you plan to publish or accept contributions, choose a license that matches how you want others to use the project.

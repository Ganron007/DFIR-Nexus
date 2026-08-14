# DFIR-Nexus Setup Guide

> **Companion to** [guide.md](guide.md) (examiner workflow) · [CLI.md](CLI.md) (command reference) · [ARCHITECTURE.md](ARCHITECTURE.md) (trust model)

This guide walks you from a bare system to a running DFIR-Nexus investigation. It covers every install path, external forensic tool requirements, multi-machine virtual machine (VM) wiring options, and environment configuration.

---

## 0. Which reader are you?

| Reader | Goal | Sections needed |
|--------|------|-----------------|
| **Solo Linux examiner** (SIFT VM, Ubuntu desktop, REMnux) | Local stdio install, one analyst | 1 → 2 → 3 → 5 → 8 → 9 |
| **Solo Windows examiner** (analyst workstation) | Run on Windows, native Zimmerman / KAPE tools | 1 → 2 → 3 → 4 → 8 → 9 |
| **Multi-machine lab** (SIFT + Windows VMs, one LLM client) | One LLM, two `nexus serve --http` instances | 1 → 2 → 3 → 4 → 6 → 7 → 8 → 9 |
| **Headless / CI install** | Automated, no interactive prompts | 1 → 2 (`--skip-init --skip-password`) → 9 (verification) |
| **MCP integrator** (writing another agent) | Just the API surface | 1 → 2 → 3 (skip 5) → API exploration |

If you are a solo Linux or Windows examiner — ~80% of readers — skip §6 (multi-machine wiring) and §7b (multi-nexus client). You can be at "first case" in about 15 minutes.

---

## 1. System Prerequisites

DFIR-Nexus orchestrates other forensic utilities. To run those tools, your system needs basic prerequisites:

| Dependency | Minimum | Linux | macOS | Windows | Mapped Feature |
|-----------|---------|-------|-------|---------|----------------|
| **Python** | 3.12+ | `apt install python3.12 python3.12-venv` | `brew install python@3.12` | `winget install Python.Python.3.12` | Core server & CLI |
| **`pip`** | bundled | bundled with Python | bundled | bundled | Package manager |
| **Git** | any | `apt install git` | `xcode-select --install` | `winget install Git.Git` | Installation & source updates |
| **build-essential** | — | `apt install build-essential` | n/a (Xcode CLT) | n/a (wheels ship prebuilt) | RAG / SQLite compile fallbacks |
| **Docker (optional)** | any | `apt install docker.io` | Docker Desktop | Docker Desktop | Running integrations (OSearch) |
| **PowerShell 7+** | 7.x | `apt install powershell` | `brew install powershell` | Pre-installed / `winget install Microsoft.PowerShell` | Setup scripts & Windows commands |

**Exit condition:** `python3 --version` (or `python --version` on Windows) shows ≥ 3.12.

---

## 2. Install the DFIR-Nexus Package

### 2a. Setup script (recommended)
Execute the appropriate script from the repository root:

```bash
# Linux (SIFT, Ubuntu, REMnux, Debian — any Bash-capable host)
./setup-linux.sh

# macOS (Apple Silicon + Intel)
./setup-macos.sh

# Windows (PowerShell 7+, run from repo root)
.\setup-windows.ps1
```

**What each script does:**
1. Verifies Python 3.12+ is installed and on the PATH.
2. Creates a virtual environment at `.venv/` (unless `--no-venv` is passed).
3. Installs DFIR-Nexus and all extras via `pip install -e .[all]`.
4. Prompts for **examiner identity** (`nexus config --examiner "..."`).
5. Prompts for **approval password** (`nexus config --setup-password`).
6. Runs `nexus init` to verify SQLite and write basic configuration.

**Flags** (can be passed in any order):
- `--skip-init`: Stop immediately after package installation (ideal for automated CI).
- `--skip-password`: Skip setting up the approval password (you must run `nexus config --setup-password` later).
- `--no-venv`: Install package into your active global/user Python environment instead of creating `.venv/`.

### 2b. Pip install (manual control)
If you prefer not to use setup scripts, run:
```bash
pip install dfir-nexus[all]
```
The `[all]` extras bundle contains:
- `[http]`: Starlette + Uvicorn (needed for the Examiner Portal web dashboard).
- `[rag]`: ChromaDB + sentence-transformers (needed for forensic knowledge semantic search).
- `[triage]`: orjson + zstandard (needed for matching Windows baselines).
- `[dfir]`: Native artifact parsers — python-evtx (EVTX), regipy (registry hives), pylnk3 (LNK shortcuts).
- `[opencti]`: OpenCTI threat intelligence client.
- `[encrypt]`: Cryptography (for encrypted case exports).
- `[detection]`: PySigma (for translating Sigma rules to KQL/Splunk/etc.).
- `[pipeline]`: LangGraph + LangChain providers (for the LLM-driven investigation pipeline).

Configure identity and approval password manually:
```bash
nexus config --examiner "alice"
nexus config --setup-password    # Prompts for approval password
nexus init
```

### 2d. LLM pipeline configuration (optional, agentic mode)

The `nexus pipeline` command drives an LLM investigation graph (evidence →
hunt → DRAFT findings → your approval). Create a `.env` in the working
directory (gitignored — never commit it):

```bash
NEXUS_LLM_MODEL=your-model-name          # e.g. gpt-4o, step-3.7-flash
NEXUS_LLM_BASE_URL=https://your-endpoint/v1   # any OpenAI-compatible API
NEXUS_LLM_API_KEY=***                    # optional for local endpoints
NEXUS_LLM_PROVIDER=openai-compatible     # or: openai | anthropic | ollama
NEXUS_LLM_REASONING=high                 # optional reasoning passthrough
```

`NEXUS_LLM_PROVIDER` is optional — it defaults to `openai-compatible` whenever
`NEXUS_LLM_BASE_URL` is set, which works with any OpenAI-compatible service
(OpenAI, StepFun, LiteLLM, vLLM, Ollama `/v1`, ...). Legacy
`NEXUS_MODEL="provider/model"` routing still works.

### 2e. RAG index and triage baselines

Both knowledge stores are looked for locally first (`~/.nexus/data/rag`,
`~/.nexus/data/triage`) — copy or build your own, or download the prebuilt
releases via `forensic_rag_download()` / `triage_download()`.

RAG is served **only on the Windows examiner MCP** (`nexus serve --http`).
SIFT does not load torch/Chroma. The pipeline (and any other client) calls
`forensic_rag_search` over HTTP on the Windows host.

- `NEXUS_RAG_MODEL` (alias `NEXUS_RAG_EMBED_MODEL`) — HuggingFace id **or**
  a local snapshot directory. Default: `BAAI/bge-base-en-v1.5`.
  This **must** match the embeddings in the Chroma index (`metadata.json`
  → `"model"`). On first load, DFIR-Nexus resolves the id against the local
  HuggingFace hub cache (`~/.cache/huggingface/hub/models--BAAI--bge-base-en-v1.5`)
  and sets `local_files_only=True` so it does not hit the network.
- `NEXUS_RAG_MODEL_REVISION` — hub ref (default `main`).
- `NEXUS_RAG_RELEASE_REPO` / `NEXUS_TRIAGE_RELEASE_REPO` — point at your own
  GitHub release assets (`owner/repo`) instead of the default source.

`forensic_rag_status()` reports `model`, `model_load_path`, `model_source`
(`hf_hub_cache` | `explicit_dir` | `huggingface_id`), and `local_files_only`.

### 2c. From source (contributors)
```bash
git clone https://github.com/Unallocated/DFIR-Nexus.git
cd DFIR-Nexus
python -m venv .venv
source .venv/bin/activate      # Linux / macOS
.venv\Scripts\Activate.ps1     # Windows (PowerShell)

pip install -e .[all]
```

**Exit condition:** `nexus --version` prints the version string.

---

## 2.5 Environment before any investigation (required)

Do this **once per analysis host** before `nexus pipeline`, Rocba, or MCP clients.
A missing parser is a **setup failure**, not an acceptable SKIP in the tool ledger.

| Order | What | How you know it worked |
|------|------|------------------------|
| 1 | Package + extras | `pip install -e ".[all]"` — includes LangGraph / LangChain (`[pipeline]`) |
| 2 | Portable forensic binaries | Windows: `pwsh -File tools/fetch-windows-tools.ps1`. SIFT: `bash tools/fetch-linux-tools.sh`. Layout: [tools/README.md](../tools/README.md) |
| 3 | Python deps for those parsers | Fetch vendors ANSSI `bits`+`construct` **inside** `Tools/.../BitsParser/` (do not `pip install bits_parser` into the Nexus interpreter — it pins `construct==2.8.12` and breaks `regipy`). KStrike needs `pip install libesedb-python` in the `nexus serve` interpreter |
| 4 | Core SIFT packages | `vol`, `fls`, `mactime` on PATH (SIFT VM / apt). Not optional for memory/disk jobs |
| 5 | Doctor | `nexus doctor` → `golden-path: ok`. Core EZ/Hayabusa **and** `bmc-tools.py` / `BitsParser.py` must resolve |
| 6 | MCP | `nexus serve --http` on each analysis host (`127.0.0.1:4508` Windows, SIFT on its lab IP) |
| 7 | RAG (coverage/design only) | Windows MCP `forensic_rag_status` = ready. Tools mode does not load RAG |

KAPE stays operator-downloaded (Kroll). Thumbcache Viewer CMD and LogFileParser stay cataloged until their CLI is verified — they are not silent SKIPs for missing bits/RDP parsers.

---

## 3. Install Forensic Tools

DFIR-Nexus wraps external forensic command-line tools. Put portable copies under `Tools/windows/` or `Tools/linux/` (gitignored) using the fetch scripts in §2.5. **Do not treat "tool not installed" as a successful run.**

### 3a. Windows Forensic Tools Installation

To run Zimmerman tools, KAPE, Hayabusa, Chainsaw, Capa, and Yara natively on Windows, follow these installation procedures.

#### Option A: Installing via Chocolatey (Simplest)
Chocolatey is a Windows package manager. If you do not have it, install it by opening an administrator PowerShell prompt and running:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```
Once Chocolatey is installed, run the following commands to install the required forensic tools:
```powershell
# Eric Zimmerman's Tools (PECmd, MFTECmd, RECmd, SBECmd, etc.)
choco install ericzimmerman -y

# KAPE (Kroll Artifact Parser and Extractor)
choco install kape -y

# Sigma / Event Log Hunting Tools
choco install hayabusa -y
choco install chainsaw -y

# Static Analysis and Threat Hunting
choco install yara -y
```

#### Option B: Manual Installation
If you cannot use Chocolatey, download the tools manually:
1. **Zimmerman Tools**: Download Eric Zimmerman's tools downloader script [Get-ZimmermanTools.ps1](https://f001.backblazeb0.com/file/EricZimmermanTools/Get-ZimmermanTools.ps1) and run it in a directory (e.g. `C:\Forensics\Zimmerman`).
2. **KAPE**: Download KAPE from [Kroll's official site](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor) and extract it to `C:\Forensics\kape`.
3. **Hayabusa / Chainsaw**: Download from their respective GitHub Release pages ([Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa/releases) and [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw/releases)) and extract them.
4. **Capa**: Install via python: `pip install flare-capa`.
5. **Memory Acquisition & Analysis (WinPmem, DumpIt, Moneta)**:
   - WinPmem: Download from [Velocidex/WinPmem](https://github.com/Velocidex/WinPmem/releases) and place `winpmem.exe` in your path.
   - Moneta: Download from [forrest-orr/moneta](https://github.com/forrest-orr/moneta/releases).

---

### 3b. Linux / SIFT Workstation Installation

To run Volatility, Plaso, SleuthKit, Zeek, Yara, and other command-line utilities, you need a Linux environment.

#### Option A: Using SANS SIFT Workstation VM (Recommended)
The **SIFT (SANS Investigative Forensic Toolkit)** Workstation VM contains almost all these tools pre-configured:
1. Download the prebuilt SIFT Workstation Virtual Appliance (OVA format) from the [SANS Portal](https://www.sans.org/tools/sift-workstation/).
2. Import it into VMware Workstation, VMware Fusion, or VirtualBox.
3. SIFT 2024+ includes Python 3.12 out-of-the-box. Run setup scripts directly inside the VM.

*Alternatively, install SIFT tools onto a clean Ubuntu 22.04 LTS system using the SIFT CLI:*
```bash
wget https://github.com/sans-dfir/sift-cli/releases/download/v1.14.0/sift-cli-linux
chmod +x sift-cli-linux
sudo mv sift-cli-linux /usr/local/bin/sift
sudo sift install
```

#### Option B: Manual Tool Installation on Ubuntu 22.04 / 24.04
If you are using a standard Ubuntu host and do not want to install the entire SIFT suite, install individual packages:
```bash
# 1. Install SleuthKit, Yara, Tshark, and bulk_extractor
sudo apt update && sudo apt install -y sleuthkit yara tshark bulk-extractor

# 2. Install Plaso (log2timeline) via the GIFT PPA repository
sudo add-apt-repository ppa:gift/stable -y
sudo apt update && sudo apt install -y plaso-tools

# 3. Install Volatility 3
git clone https://github.com/volatilityfoundation/volatility3.git /opt/volatility3
cd /opt/volatility3 && pip install -r requirements.txt
sudo ln -s /opt/volatility3/vol.py /usr/local/bin/vol

# 4. Install Hayabusa
wget https://github.com/Yamato-Security/hayabusa/releases/download/v2.18.0/hayabusa-2.18.0-lin-x64.zip
unzip hayabusa-2.18.0-lin-x64.zip -d /opt/hayabusa
sudo ln -s /opt/hayabusa/hayabusa /usr/local/bin/hayabusa
```

---

### 3c. How DFIR-Nexus Resolves Executables

DFIR-Nexus resolves binaries when you call `run_command` (Linux) or `run_windows_command` (Windows):
1. **Windows:** `NEXUS_TOOL_PATHS` / `tool_paths` in `~/.nexus/config.yaml`, then the repo folder `Tools/windows/` (including Zimmerman `net9/` and versioned Hayabusa/Suzaku names). System `PATH` is **not** searched — personal copies of PECmd/EvtxECmd elsewhere are ignored.
2. **Linux/SIFT:** `PATH` (`shutil.which`), then `NEXUS_TOOL_PATHS` / `tool_paths`.
3. Specialized checks occur for variables like `NEXUS_HAYABUSA_DIR` (defaults to `/opt/hayabusa` on Linux).

#### Setting up `NEXUS_TOOL_PATHS`
If you installed your forensic tools in a custom directory (e.g. `C:\ForensicTools` on Windows or `/opt/forensics` on Linux), configure the path so DFIR-Nexus can find them:

*On Windows (PowerShell):*
```powershell
# Set for current session
$env:NEXUS_TOOL_PATHS = "C:\ForensicTools;C:\Program Files\KAPE"
# Or write to configuration file permanently:
nexus config --show # Find config path
```

*On Linux (Bash):*
```bash
export NEXUS_TOOL_PATHS="/opt/forensics:/opt/volatility3"
```
> [!NOTE]
> When defining multiple directories in `NEXUS_TOOL_PATHS` via environment variables, use the system PATH separator: `;` on Windows, `:` on Linux. In `config.yaml` it is represented as a YAML list.

---

## 4. Configure Identity & Secrets

Both steps are required before the first case is opened. Both are terminal-only for security — no Web UI or LLM client can set your password.

### Set your examiner name
```bash
nexus config --examiner "alicesmith"
```
This writes `~/.nexus/config.yaml` with your examiner identifier. This identifier is converted to a lowercase, sanitized slug (e.g., `Alice Smith` → `alicesmith`). It is embedded in finding IDs (`F-alicesmith-001`), timeline events, audit trails, and HMAC signatures.

### Set the approval password
```bash
nexus config --setup-password
```
You are prompted **twice** via `getpass` (no echo). The password:
- Must be at least **8 characters**.
- Is hashed with **PBKDF2-SHA256** (600,000 iterations, 32-byte random salt) and stored at `~/.nexus/passwords/<examiner>.json` (`0o600`).
- Is never stored in plaintext.

> [!WARNING]
> The approval password is the human-in-the-loop trust boundary. Without it, `nexus approve` and the portal commit workflow refuse to run. The AI cannot bypass this block.

**Exit condition:** `nexus config --show` shows `password_set: true`.

---

## 5. VM and Lab Network Setup

In a professional environment (or when testing a multi-VM lab ecosystem), you will run DFIR-Nexus across distinct Virtual Machines (SIFT VM for Linux analysis, Windows Analyst VM for Zimmerman/KAPE parsing, and a Host/Client machine for the LLM agent).

```
                     ┌──────────────────────┐
                     │  LLM client          │
                     │  (Claude Code, etc.) │
                     │  IP: 192.0.2.1    │
                     └────┬──────────┬──────┘
                          │          │
           ┌──────────────┘          └──────────────┐
           ▼ (HTTPS / Port 4508)                    ▼ (HTTPS / Port 4508)
  ┌──────────────────────┐                 ┌──────────────────────┐
  │ SIFT VM (Linux)      │                 │ Windows Analyst VM   │
  │ IP: 192.0.2.41    │                 │ IP: 192.0.2.42    │
  │                      │                 │                      │
  │ nexus serve --http   │                 │ nexus serve --http   │
  │ --host 0.0.0.0       │                 │ --host 0.0.0.0       │
  │                      │                 │                      │
  │ Mounts: /evidence/   │                 │ Shares: C:\evidence  │
  └──────────────────────┘                 └──────────────────────┘
```

### 5a. Network Configuration
1. Ensure your VMs are configured with **Host-Only** or **Bridged** networking in VMware Workstation / VirtualBox so they can ping one another.
2. Determine the IP addresses of your VMs:
   - SIFT IP: `192.0.2.41`
   - Windows IP: `192.0.2.42`
3. Configure the firewall on both VMs to allow incoming TCP traffic on port `4508`.
   - On Linux (SIFT): `sudo ufw allow 4508/tcp`
   - On Windows: Add an Inbound Rule in Windows Advanced Firewall for Port `4508`.

### 5b. Evidence share (Windows owns the mount; SIFT maps it)

**Design decision:** the KAPE/triage volume is mounted **once on Windows**
(e.g. `H:\C`). Windows **SMB-shares** that tree. SIFT **CIFS-mounts** it at
`/mnt/windows_mount` (the stock SIFT mount point). Both toolsets then see
the **same bytes**:

| Host | Path | Tools |
|------|------|--------|
| Windows | `H:\C` (`NEXUS_SHARE_ROOT`) | Zimmerman, Hayabusa, … |
| SIFT | `/mnt/windows_mount` (`NEXUS_SIFT_TRIAGE_ROOT`) | Plaso `log2timeline`/`psort`, TSK, RegRipper |

SIFT already exports Samba `[cases]` (`/cases`, writable) and `[mnt]`
(`/mnt`, read-only). Use `\\<sift>\cases` from Windows to read Plaso output.
Do **not** put the HuggingFace/Chroma RAG index on this share.

Lab helper (elevated): `scripts/lab_share_kape.ps1` creates share `kape` on
`H:\C` and mounts it on SIFT. SCP is fallback only.

```powershell
# Windows (elevated)
.\scripts\lab_share_kape.ps1
$env:NEXUS_SHARE_ROOT = "H:\C"
```

```bash
# SIFT (if the script did not mount)
sudo mkdir -p /mnt/windows_mount
sudo mount -t cifs //192.168.77.1/kape /mnt/windows_mount -o guest,ro,vers=3.0,uid=1000,gid=1000
export NEXUS_SIFT_TRIAGE_ROOT=/mnt/windows_mount
export NEXUS_SHARE_ROOT=/mnt/windows_mount
```

Super-timeline (FOR508): `log2timeline.py --parsers 'win7,!filestat'` against
the **mounted triage directory**. It does **not** need an E01. Full-disk E01
is a different investigation.

---

## 6. Multi-Machine Wiring

For network security, always configure a bearer token before exposing DFIR-Nexus over the network.

### Step 1: Start servers with Bearer Authentication
Run these commands on their respective VM hosts.

*On SIFT VM (Linux):*
```bash
export NEXUS_BEARER_TOKEN="secure-passphrase-token-sift"
nexus serve --http --host 0.0.0.0 --port 4508
```

*On Windows VM:*
```powershell
$env:NEXUS_BEARER_TOKEN = "secure-passphrase-token-windows"
nexus serve --http --host 0.0.0.0 --port 4508
```

### Step 2: Generate the Client configuration
On your examiner/client host (running Claude Code or Cursor), configure the client to communicate with both servers:
```bash
nexus setup client --sift 192.0.2.41:4508 --windows 192.0.2.42:4508 --bearer "secure-passphrase-token-sift"
```
*(If SIFT and Windows tokens differ, edit the generated `.mcp.json` or global configuration file manually to assign respective bearer header tokens)*.

---

## 7. Wire your LLM Client

### 7a. Single Host (Solo Examiner)

#### Claude Code — Stdio transport (Zero Config)
Claude Code spawns DFIR-Nexus as a local subprocess. No network port is exposed. Add this to your project's `.mcp.json` or globally in `~/.claude/settings.json`:
```json
{
  "mcpServers": {
    "dfir-nexus": {
      "command": "nexus",
      "args": ["serve"]
    }
  }
}
```

#### Claude Code — HTTP transport (For Examiner Portal)
If you want the Examiner Portal web dashboard (`/portal`) running alongside the LLM, use the HTTP transport.
Start the server in a terminal:
```bash
nexus serve --http --port 4508
```
Then write this in `.mcp.json` / `~/.claude/settings.json`:
```json
{
  "mcpServers": {
    "dfir-nexus": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:4508/mcp"
    }
  }
}
```

---

### 7b. Multi-Nexus Fleet Configuration (Lab / VM Topology)

After running the client setup wizard (`nexus setup client`), your global `.mcp.json` is generated to aggregate both SIFT and Windows endpoints:
```json
{
  "mcpServers": {
    "dfir-nexus-sift": {
      "type": "streamable-http",
      "url": "http://192.0.2.41:4508/mcp",
      "headers": {
        "Authorization": "Bearer secure-passphrase-token-sift"
      }
    },
    "dfir-nexus-windows": {
      "type": "streamable-http",
      "url": "http://192.0.2.42:4508/mcp",
      "headers": {
        "Authorization": "Bearer secure-passphrase-token-windows"
      }
    }
  }
}
```

Additionally, `~/.claude/settings.json` is configured with directory security deny rules to protect case files from arbitrary modifications by the LLM:
```json
{
  "denyRules": [
    "Edit(**/CASE.yaml)",
    "Write(**/findings.json)",
    "Bash(nexus approve*)",
    "Edit(**/.nexus/**)"
  ]
}
```

**Exit condition:** The LLM client shows both `dfir-nexus-sift` and `dfir-nexus-windows` tools loaded.

---

## 8. Download Baseline Databases

Certain features (like process triage validation and RAG knowledge search) remain dormant until you retrieve their static databases. Run these commands from your LLM Client:

| Feature | MCP Tool | Size | Description |
|---------|----------|------|-------------|
| **RAG Knowledge Base** | `forensic_rag_download()` | ~600 MB | ChromaDB semantic index containing SANS material, Sigma rules, MITRE ATT&CK techniques, LOLBAS, and KAPE targets. |
| **Windows Triage Baselines** | `triage_download()` | ~2 GB | SQLite known-good baselines compiled from 2.6M+ clean Windows installations, process models, and named pipes. |

---

## 9. Verification & Troubleshooting

Check off items to ensure setup is functional:
- [ ] `nexus --version` outputs a valid version.
- [ ] `nexus config --show` prints configuration details with `password_set: true`.
- [ ] `nexus serve --http` runs successfully on port 4508.
- [ ] `nexus portal` opens the portal correctly in a web browser.
- [ ] CLI command integrity check: `nexus review verify` evaluates successfully.

For runtime issues, evidence workflows, and hands-on practice, proceed to **[guide.md](guide.md)**.

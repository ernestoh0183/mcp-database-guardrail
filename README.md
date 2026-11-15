# 🛡️ MCP Database Guardrail

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-Model%20Context%20Protocol-orange.svg)](https://modelcontextprotocol.io/)
[![Zero-Trust: Read--Only](https://img.shields.io/badge/Zero--Trust-Read--Only%20Enforced-emerald.svg)](https://www.4ruy.com)

> **Enterprise-grade Model Context Protocol (MCP) servers for secure, read-only database exploration (SQLite, PostgreSQL, MySQL) with AST guardrails and zero-trust controls.**

Official companion open-source repository for the **4Ruy.com** engineering series on AI Skills and Model Context Protocol:
* Read the technical article: [«Cómo Darle Manos a tu IA: Qué es Model Context Protocol (MCP) y Guía Práctica para Conectar Herramientas y Bases de Datos»](https://www.4ruy.com/es/como-conectar-ia-herramientas-bases-datos-mcp/)
* English version: [«Giving Hands to Your AI: What is Model Context Protocol (MCP) and a Practical Guide to Connect Tools and Databases»](https://www.4ruy.com/how-to-connect-ai-tools-databases-mcp/)

---

## 💡 The Problem: The "House Key" vs. The "Hotel Keycard"

Giving Large Language Models (LLMs) direct, unconstrained database credentials is like handing a stranger the master key to your entire house: they can open personal drawers, read sensitive records, or demolish a wall with a sledgehammer.

**MCP Database Guardrail** implements the **Hotel Keycard Architecture**:
1. **Scoped Room Access:** The AI agent is only granted access to whitelisted tables and schemas, isolating internal administration and security metadata.
2. **Read-Only Observation:** The agent can inspect the table schema and execute analytical read operations (`SELECT`, `WITH`), but is structurally blocked from destructive actions (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`).
3. **Resource Safeguards:** Enforces hard limits (`LIMIT 50`) and strict execution timeouts (`10s`) to prevent runaway Cartesian joins or memory exhaustion.

```
┌─────────────────────────────────┐
│     AI Host / Agent Client      │
│ (Claude Desktop, Cursor, etc.)  │
└────────────────┬────────────────┘
                 │ JSON-RPC 2.0 (MCP Protocol)
                 ▼
┌────────────────────────────────────────────────────────┐
│           MCP Database Guardrail Server                │
│                                                        │
│  ├── Resource: Database Schema Inspection (Read-Only)  │
│  ├── Tool: Safe SQL Execution (AST Guardrail)          │
│  └── Prompt: Business KPI Analysis Template            │
└────────────────┬───────────────────────────────────────┘
                 │ Strict SELECT / Read-Only Transaction
                 ▼
┌─────────────────────────────────┐
│     Target Database Engine      │
│  (SQLite / PostgreSQL / MySQL)  │
└─────────────────────────────────┘
```

---

## 🚀 Key Features

* **Zero-Dependency Quickstart:** Run locally in 10 seconds with `server_sqlite.py` (automatically seeds an `empresa_demo.db` dataset).
* **Multi-Engine Support:** Ready-to-use production servers for **SQLite**, **PostgreSQL**, and **MySQL**.
* **AST & Token Guardrails:** Programmatic rejection of dangerous keywords, multi-statement injection attempts, and DDL mutations.
* **Automatic `LIMIT` Enforcement:** Appends `LIMIT 50` if omitted by the model, preventing buffer overflows.
* **Native MCP Components:**
  * **Resources (`schema`):** Allows models to understand relational schemas without consuming execution tokens blindly.
  * **Tools (`ejecutar_consulta_segura`):** Controlled query execution returning structured JSON with latency metrics.
  * **Prompts (`asistente_kpis_negocio`):** Standard operating guidelines for autonomous data analysis.

---

## 📦 Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/ernestoh0183/mcp-database-guardrail.git
cd mcp-database-guardrail
```

### 2. Create virtual environment & install dependencies
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -e .
```

---

## 🛠️ Configuration for AI Clients

Add the server to your favorite MCP-compatible client configuration file:

### Claude Desktop (`claude_desktop_config.json`)
* **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
* **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "sqlite-guardrail": {
      "command": "python",
      "args": [
        "/absolute/path/to/mcp-database-guardrail/server_sqlite.py"
      ],
      "env": {
        "SQLITE_DB_PATH": "empresa_demo.db"
      }
    }
  }
}
```

### Cursor (`.cursor/mcp.json` or Settings -> Features -> MCP)
```json
{
  "mcpServers": {
    "postgres-guardrail": {
      "command": "python",
      "args": [
        "/absolute/path/to/mcp-database-guardrail/server_postgres.py"
      ],
      "env": {
        "PG_HOST": "localhost",
        "PG_PORT": "5432",
        "PG_DATABASE": "empresa_prod",
        "PG_USER": "readonly_ai_user",
        "PG_PASSWORD": "your_secure_password_here",
        "PG_SCHEMA": "public"
      }
    }
  }
}
```

---

## 🧪 Quick Test in Terminal

You can test the server directly with the official MCP Inspector:
```bash
npx @modelcontextprotocol/inspector python server_sqlite.py
```

Then ask your AI agent:
> *"Show me the top 3 best-selling products this month and their total revenue."*

The model will:
1. Inspect `sqlite://schema` to locate the `pedidos` and `productos` tables.
2. Draft a `SELECT` query with `JOIN` and `GROUP BY`.
3. Invoke `ejecutar_consulta_segura` through the MCP protocol.
4. Return an executive summary with verified, grounded figures.

---

## 📄 License & Attribution

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

* **Author:** Rodrigo Ernesto Hernández Buitrago
* **Website:** [https://www.4ruy.com](https://www.4ruy.com)
* **LinkedIn:** [Rodrigo Ernesto Hernández Buitrago](https://www.linkedin.com/in/rodrigo-ernesto-hernandez-buitrago-786b09113/)

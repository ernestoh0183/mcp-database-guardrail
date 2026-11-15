"""
Enterprise PostgreSQL MCP Server with Zero-Trust Read-Only Guardrails.
Author: Rodrigo Ernesto Hernández Buitrago (4Ruy.com)
License: MIT
"""

import os
import re
import time
from typing import Dict, Any, List
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv

load_dotenv()

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None

mcp = FastMCP("Secure-PostgreSQL-Guardrail")

PG_HOST = os.environ.get("PG_HOST", "localhost")
PG_PORT = int(os.environ.get("PG_PORT", "5432"))
PG_DATABASE = os.environ.get("PG_DATABASE", "empresa_prod")
PG_USER = os.environ.get("PG_USER", "readonly_ai_user")
PG_PASSWORD = os.environ.get("PG_PASSWORD", "")
PG_SCHEMA = os.environ.get("PG_SCHEMA", "public")

BLOCKED_KEYWORDS = {
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE",
    "CREATE", "REPLACE", "GRANT", "REVOKE", "EXEC", "EXECUTE",
    "COPY", "VACUUM", "REINDEX", "CALL", "DO", "LOCK"
}

def get_connection():
    if psycopg2 is None:
        raise RuntimeError("La librería 'psycopg2-binary' no está instalada. Ejecute 'pip install psycopg2-binary'.")
    
    conn = psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DATABASE,
        user=PG_USER,
        password=PG_PASSWORD,
        connect_timeout=5
    )
    # Enforce read-only session at database engine level
    conn.set_session(readonly=True, autocommit=True)
    with conn.cursor() as cur:
        # Enforce statement timeout to prevent denial-of-service queries
        cur.execute("SET statement_timeout = '10s';")
    return conn

def validate_readonly_sql(query: str) -> None:
    cleaned = query.strip()
    statements = [s.strip() for s in cleaned.split(";") if s.strip()]
    if len(statements) > 1:
        raise ValueError("Violación de Seguridad: Ejecución múltiple de sentencias prohibida.")
    
    single_stmt = statements[0] if statements else ""
    first_word = single_stmt.split()[0].upper() if single_stmt.split() else ""
    if first_word not in ("SELECT", "WITH", "EXPLAIN"):
        raise ValueError(f"Violación de Seguridad: Solo se permiten consultas SELECT/WITH. Se rechazó '{first_word}'.")
    
    tokens = re.findall(r'\b[A-Za-z_]+\b', single_stmt.upper())
    for token in tokens:
        if token in BLOCKED_KEYWORDS:
            raise ValueError(f"Violación de Seguridad: Palabra clave destructiva detectada '{token}'. Operación abortada.")

@mcp.resource("postgres://schema")
def get_postgres_schema() -> str:
    """Proporciona el esquema DDL y columnas de las tablas autorizadas en PostgreSQL."""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("""
    SELECT table_name, column_name, data_type, is_nullable
    FROM information_schema.columns
    WHERE table_schema = %s
    ORDER BY table_name, ordinal_position;
    """, (PG_SCHEMA,))
    
    columns = cur.fetchall()
    conn.close()
    
    if not columns:
        return f"=== NO SE ENCONTRARON TABLAS EN EL ESQUEMA '{PG_SCHEMA}' ==="
        
    schema_map = {}
    for col in columns:
        t = col['table_name']
        if t not in schema_map:
            schema_map[t] = []
        schema_map[t].append(f"  * {col['column_name']} ({col['data_type']}) - Nullable: {col['is_nullable']}")
        
    lines = [f"=== ESQUEMA POSTGRESQL AUTORIZADO (Esquema: {PG_SCHEMA}) ==="]
    for t_name, cols in schema_map.items():
        lines.append(f"\nTabla: {t_name}")
        lines.extend(cols)
        
    return "\n".join(lines)

@mcp.tool()
def ejecutar_consulta_segura(sql: str, max_filas: int = 50) -> Dict[str, Any]:
    """Ejecuta una consulta SQL de solo lectura en PostgreSQL con protección de tiempo límite y tope de filas."""
    t0 = time.time()
    validate_readonly_sql(sql)
    
    max_filas = min(max(1, max_filas), 200)
    query_clean = sql.strip().rstrip(";")
    if not re.search(r'\bLIMIT\b', query_clean, re.IGNORECASE):
        query_clean = f"{query_clean} LIMIT {max_filas}"
        
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cur.execute(query_clean)
        rows = cur.fetchall()
        columnas = [desc[0] for desc in cur.description] if cur.description else []
        duracion_ms = round((time.time() - t0) * 1000, 2)
        
        return {
            "status": "success",
            "filas_retornadas": len(rows),
            "columnas": columnas,
            "duracion_ms": duracion_ms,
            "datos": rows
        }
    except Exception as e:
        return {
            "status": "error",
            "mensaje": f"Error PostgreSQL: {str(e)}",
            "duracion_ms": round((time.time() - t0) * 1000, 2)
        }
    finally:
        conn.close()

if __name__ == "__main__":
    mcp.run()

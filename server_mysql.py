"""
Enterprise MySQL MCP Server with Zero-Trust Read-Only Guardrails.
Author: Rodrigo Ernesto Hernández Buitrago (4Ruy.com)
License: MIT
"""

import os
import re
import time
from typing import Dict, Any
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv

load_dotenv()

try:
    import pymysql
    import pymysql.cursors
except ImportError:
    pymysql = None

mcp = FastMCP("Secure-MySQL-Guardrail")

MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "empresa_prod")
MYSQL_USER = os.environ.get("MYSQL_USER", "readonly_ai")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")

BLOCKED_KEYWORDS = {
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE",
    "CREATE", "REPLACE", "GRANT", "REVOKE", "EXEC", "EXECUTE",
    "LOCK", "CALL"
}

def get_connection():
    if pymysql is None:
        raise RuntimeError("La librería 'pymysql' no está instalada. Ejecute 'pip install pymysql'.")
    
    return pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        cursorclass=pymysql.cursors.DictCursor,
        read_timeout=10,
        write_timeout=5,
        autocommit=True
    )

def validate_readonly_sql(query: str) -> None:
    cleaned = query.strip()
    statements = [s.strip() for s in cleaned.split(";") if s.strip()]
    if len(statements) > 1:
        raise ValueError("Violación de Seguridad: Ejecución múltiple de sentencias prohibida.")
    
    single_stmt = statements[0] if statements else ""
    first_word = single_stmt.split()[0].upper() if single_stmt.split() else ""
    if first_word not in ("SELECT", "WITH", "EXPLAIN"):
        raise ValueError(f"Violación de Seguridad: Solo se permiten consultas de lectura (SELECT/WITH). Se rechazó '{first_word}'.")
    
    tokens = re.findall(r'\b[A-Za-z_]+\b', single_stmt.upper())
    for token in tokens:
        if token in BLOCKED_KEYWORDS:
            raise ValueError(f"Violación de Seguridad: Palabra clave destructiva detectada '{token}'. Operación abortada.")

@mcp.resource("mysql://schema")
def get_mysql_schema() -> str:
    """Proporciona el esquema DDL y columnas de las tablas autorizadas en MySQL."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
            SELECT table_name, column_name, column_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = %s
            ORDER BY table_name, ordinal_position;
            """, (MYSQL_DATABASE,))
            columns = cur.fetchall()
            
        if not columns:
            return f"=== NO SE ENCONTRARON TABLAS EN LA BASE DE DATOS '{MYSQL_DATABASE}' ==="
            
        schema_map = {}
        for col in columns:
            t = col['table_name']
            if t not in schema_map:
                schema_map[t] = []
            schema_map[t].append(f"  * {col['column_name']} ({col['column_type']}) - Nullable: {col['is_nullable']}")
            
        lines = [f"=== ESQUEMA MYSQL AUTORIZADO (Base de Datos: {MYSQL_DATABASE}) ==="]
        for t_name, cols in schema_map.items():
            lines.append(f"\nTabla: {t_name}")
            lines.extend(cols)
            
        return "\n".join(lines)
    finally:
        conn.close()

@mcp.tool()
def ejecutar_consulta_segura(sql: str, max_filas: int = 50) -> Dict[str, Any]:
    """Ejecuta una consulta SQL de solo lectura en MySQL con protección de tiempo límite y tope de filas."""
    t0 = time.time()
    validate_readonly_sql(sql)
    
    max_filas = min(max(1, max_filas), 200)
    query_clean = sql.strip().rstrip(";")
    if not re.search(r'\bLIMIT\b', query_clean, re.IGNORECASE):
        query_clean = f"{query_clean} LIMIT {max_filas}"
        
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(query_clean)
            rows = cur.fetchall()
            columnas = list(rows[0].keys()) if rows else []
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
            "mensaje": f"Error MySQL: {str(e)}",
            "duracion_ms": round((time.time() - t0) * 1000, 2)
        }
    finally:
        conn.close()

if __name__ == "__main__":
    mcp.run()

"""
Secure SQLite MCP Server with Zero-Trust Read-Only Guardrails.
Author: Rodrigo Ernesto Hernández Buitrago (4Ruy.com)
License: MIT
"""

import os
import sqlite3
import time
import re
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Initialize FastMCP Server
mcp = FastMCP("Secure-SQLite-Guardrail")

DB_PATH = os.environ.get("SQLITE_DB_PATH", "empresa_demo.db")

# Blocked SQL keywords (DML & DDL operations)
BLOCKED_KEYWORDS = {
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", 
    "CREATE", "REPLACE", "ATTACH", "DETACH", "PRAGMA", "VACUUM",
    "GRANT", "REVOKE", "EXEC", "EXECUTE"
}

def init_demo_db():
    """Seed demo database if not present."""
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Schema
        cur.execute("""
        CREATE TABLE clientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            email TEXT NOT NULL,
            pais TEXT NOT NULL,
            fecha_registro DATE NOT NULL
        )
        """)
        
        cur.execute("""
        CREATE TABLE productos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sku TEXT UNIQUE NOT NULL,
            nombre TEXT NOT NULL,
            categoria TEXT NOT NULL,
            precio_unitario REAL NOT NULL,
            stock_actual INTEGER NOT NULL
        )
        """)
        
        cur.execute("""
        CREATE TABLE pedidos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente_id INTEGER NOT NULL,
            producto_id INTEGER NOT NULL,
            cantidad INTEGER NOT NULL,
            total_usd REAL NOT NULL,
            fecha_pedido DATE NOT NULL,
            estado TEXT NOT NULL,
            FOREIGN KEY (cliente_id) REFERENCES clientes (id),
            FOREIGN KEY (producto_id) REFERENCES productos (id)
        )
        """)
        
        # Seed Data
        cur.executemany("""
        INSERT INTO clientes (nombre, email, pais, fecha_registro) VALUES (?, ?, ?, ?)
        """, [
            ("Inversiones Alpha", "contacto@alpha.com", "Colombia", "2026-01-15"),
            ("Logística Beta", "ops@betalog.com", "México", "2026-02-10"),
            ("Tech Innovations Gamma", "it@gamma.tech", "España", "2026-03-05"),
            ("Agro Delta Corp", "gerencia@delta.ag", "Colombia", "2026-03-22"),
            ("Distribuciones Epsilon", "compras@epsilon.mx", "México", "2026-04-12")
        ])
        
        cur.executemany("""
        INSERT INTO productos (sku, nombre, categoria, precio_unitario, stock_actual) VALUES (?, ?, ?, ?, ?)
        """, [
            ("SRV-001", "Sensor IoT Humedad Suelo", "Hardware", 120.00, 45),
            ("SRV-002", "Gateway LoRaWAN Industrial", "Hardware", 450.00, 18),
            ("LIC-001", "Licencia Dashboard BI Anual", "Software", 1200.00, 999),
            ("SRV-003", "Cámara Multiespectral RGB", "Hardware", 850.00, 12),
            ("LIC-002", "Módulo Machine Learning Add-on", "Software", 600.00, 999)
        ])
        
        cur.executemany("""
        INSERT INTO pedidos (cliente_id, producto_id, cantidad, total_usd, fecha_pedido, estado) VALUES (?, ?, ?, ?, ?, ?)
        """, [
            (1, 1, 10, 1200.00, "2026-10-05", "Entregado"),
            (1, 2, 2, 900.00, "2026-10-08", "Entregado"),
            (2, 3, 1, 1200.00, "2026-10-15", "Facturado"),
            (3, 4, 3, 2550.00, "2026-10-22", "Entregado"),
            (4, 1, 15, 1800.00, "2026-11-02", "En tránsito"),
            (5, 5, 2, 1200.00, "2026-11-08", "Facturado")
        ])
        
        conn.commit()
        conn.close()

# Ensure demo DB exists on startup
init_demo_db()

def validate_readonly_sql(query: str) -> None:
    """Validate query against destructive patterns and multi-statement execution."""
    cleaned = query.strip()
    
    # 1. Reject multiple statements (separated by semicolon)
    statements = [s.strip() for s in cleaned.split(";") if s.strip()]
    if len(statements) > 1:
        raise ValueError("Violación de Seguridad: Ejecución múltiple de sentencias prohibida.")
    
    single_stmt = statements[0] if statements else ""
    
    # 2. Must begin strictly with SELECT or WITH (for CTEs)
    first_word = single_stmt.split()[0].upper() if single_stmt.split() else ""
    if first_word not in ("SELECT", "WITH", "EXPLAIN"):
        raise ValueError(f"Violación de Seguridad: Solo se permiten consultas de lectura (SELECT/WITH). Se rechazó '{first_word}'.")
    
    # 3. Check for forbidden keywords anywhere in query tokens
    tokens = re.findall(r'\b[A-Za-z_]+\b', single_stmt.upper())
    for token in tokens:
        if token in BLOCKED_KEYWORDS:
            raise ValueError(f"Violación de Seguridad: Palabra clave destructiva detectada '{token}'. Operación abortada.")

@mcp.resource("sqlite://schema")
def get_database_schema() -> str:
    """Provides complete DDL schema of authorized tables as a read-only context resource."""
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    cur = conn.cursor()
    
    cur.execute("""
    SELECT name, sql FROM sqlite_master 
    WHERE type='table' AND name NOT LIKE 'sqlite_%'
    ORDER BY name;
    """)
    tables = cur.fetchall()
    
    schema_docs = ["=== ESQUEMA DDL DE BASE DE DATOS AUTORIZADA ==="]
    for table_name, ddl in tables:
        schema_docs.append(f"\n-- Tabla: {table_name}")
        schema_docs.append(ddl)
        
        # Fetch columns metadata
        cur.execute(f"PRAGMA table_info({table_name});")
        cols = cur.fetchall()
        schema_docs.append("   Columnas:")
        for col in cols:
            cid, cname, ctype, notnull, dflt, pk = col
            pk_str = " [PRIMARY KEY]" if pk else ""
            schema_docs.append(f"     * {cname} ({ctype}){pk_str}")
            
    conn.close()
    return "\n".join(schema_docs)

@mcp.tool()
def ejecutar_consulta_segura(sql: str, max_filas: int = 50) -> Dict[str, Any]:
    """
    Ejecuta una consulta SQL de solo lectura (SELECT) en la base de datos con límite forzado y filtros de seguridad.
    
    Args:
        sql: Sentencia SELECT a ejecutar.
        max_filas: Límite máximo de registros a devolver (por defecto 50, máx 200).
    """
    t0 = time.time()
    validate_readonly_sql(sql)
    
    max_filas = min(max(1, max_filas), 200)
    
    # Enforce LIMIT if absent
    query_clean = sql.strip().rstrip(";")
    if not re.search(r'\bLIMIT\b', query_clean, re.IGNORECASE):
        query_clean = f"{query_clean} LIMIT {max_filas}"
    
    # Open read-only connection
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    try:
        cur.execute(query_clean)
        rows = cur.fetchall()
        columnas = [d[0] for d in cur.description] if cur.description else []
        resultados = [dict(row) for row in rows]
        duracion_ms = round((time.time() - t0) * 1000, 2)
        
        return {
            "status": "success",
            "filas_retornadas": len(resultados),
            "columnas": columnas,
            "duracion_ms": duracion_ms,
            "datos": resultados
        }
    except Exception as e:
        return {
            "status": "error",
            "mensaje": f"Error en la ejecución de la consulta: {str(e)}",
            "duracion_ms": round((time.time() - t0) * 1000, 2)
        }
    finally:
        conn.close()

@mcp.tool()
def obtener_estadisticas_tabla(nombre_tabla: str) -> Dict[str, Any]:
    """Obtiene el conteo total de filas y metadatos de una tabla específica."""
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    cur = conn.cursor()
    
    # Whitelist tables
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    valid_tables = [r[0] for r in cur.fetchall()]
    
    if nombre_tabla not in valid_tables:
        conn.close()
        return {
            "status": "error",
            "mensaje": f"Tabla '{nombre_tabla}' no encontrada o no autorizada. Tablas válidas: {valid_tables}"
        }
        
    cur.execute(f"SELECT COUNT(*) FROM {nombre_tabla};")
    total_filas = cur.fetchone()[0]
    conn.close()
    
    return {
        "status": "success",
        "tabla": nombre_tabla,
        "total_registros": total_filas
    }

@mcp.prompt()
def asistente_kpis_negocio(pregunta_usuario: str) -> str:
    """Prompt estructurado para que el agente responda preguntas de negocio con datos de la base de datos."""
    return f"""Usted opera como un Analista de Datos Senior conectado a la base de datos empresarial mediante el servidor MCP Seguro.
Siga este procedimiento:
1. Inspeccione primero el esquema mediante el recurso 'sqlite://schema'.
2. Formule una consulta SQL de solo lectura estricta (SELECT) para responder a la pregunta del usuario.
3. Invoque la herramienta 'ejecutar_consulta_segura'.
4. Presente la respuesta en un reporte estructurado y conciso, citando los números exactos retornados.

Pregunta del usuario: {pregunta_usuario}
"""

if __name__ == "__main__":
    mcp.run()

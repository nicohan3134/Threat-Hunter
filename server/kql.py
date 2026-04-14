"""
Lightweight KQL (Kusto Query Language) parser.
Translates a subset of KQL into a PostgreSQL query against the events table.

Supported syntax:
    | where EventID == 4625
    | where Machine == "DESKTOP-01"
    | where Machine contains "DESKTOP"
    | where EventID == 4625 and Machine == "DESKTOP-01"
    | search "sometext"
    | sort by TimeGenerated desc
    | sort by EventID asc
    | take 100
"""

import re

# Map KQL field names to database column names
FIELD_MAP = {
    "eventid":       "event_id",
    "machine":       "machine",
    "log":           "log",
    "source":        "source",
    "timegenerated": "time",
    "time":          "time",
    "timestamp":     "timestamp",
}

SORT_FIELD_MAP = {
    "timegenerated": "timestamp",
    "time":          "timestamp",
    "eventid":       "event_id",
    "machine":       "machine",
}


class KQLError(Exception):
    pass


def parse(query):
    """
    Parse a KQL query string and return (sql_where, sql_order, sql_limit, params).
    Raises KQLError on invalid syntax.
    """
    where_clauses = []
    params        = []
    order_by      = "timestamp DESC"
    limit         = 200
    search_term   = None

    # Split into pipes, strip whitespace
    parts = [p.strip() for p in query.strip().split("|") if p.strip()]

    for part in parts:
        lower = part.lower()

        # ── where ────────────────────────────────────────────────────────
        if lower.startswith("where "):
            expr = part[6:].strip()
            clause, clause_params = _parse_where(expr)
            where_clauses.append(clause)
            params.extend(clause_params)

        # ── search ───────────────────────────────────────────────────────
        elif lower.startswith("search "):
            term = part[7:].strip().strip('"').strip("'")
            search_term = term
            where_clauses.append(
                "(CAST(event_id AS TEXT) ILIKE %s OR machine ILIKE %s OR source ILIKE %s OR strings ILIKE %s OR log ILIKE %s)"
            )
            like = f"%{term}%"
            params.extend([like, like, like, like, like])

        # ── sort by ──────────────────────────────────────────────────────
        elif lower.startswith("sort by ") or lower.startswith("order by "):
            rest = re.sub(r'^(sort by|order by)\s+', '', part, flags=re.IGNORECASE).strip()
            tokens = rest.split()
            field = tokens[0].lower()
            direction = tokens[1].upper() if len(tokens) > 1 else "DESC"
            if direction not in ("ASC", "DESC"):
                direction = "DESC"
            col = SORT_FIELD_MAP.get(field, "timestamp")
            order_by = f"{col} {direction}"

        # ── take / limit ─────────────────────────────────────────────────
        elif lower.startswith("take ") or lower.startswith("limit "):
            rest = re.sub(r'^(take|limit)\s+', '', part, flags=re.IGNORECASE).strip()
            try:
                limit = min(int(rest), 1000)
            except ValueError:
                raise KQLError(f"Invalid value for take/limit: {rest}")

        else:
            raise KQLError(f"Unknown operator: '{part.split()[0]}'")

    where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
    return where_sql, order_by, limit, params


def _parse_where(expr):
    """Parse a where expression, supporting 'and' joining of conditions."""
    # Split on ' and ' (case-insensitive)
    conditions = re.split(r'\s+and\s+', expr, flags=re.IGNORECASE)
    clauses = []
    params  = []

    for cond in conditions:
        c, p = _parse_condition(cond.strip())
        clauses.append(c)
        params.extend(p)

    return " AND ".join(clauses), params


def _parse_condition(cond):
    """Parse a single condition like: EventID == 4625 or Machine contains "foo"."""

    # contains
    m = re.match(r'(\w+)\s+contains\s+"([^"]*)"', cond, re.IGNORECASE)
    if not m:
        m = re.match(r"(\w+)\s+contains\s+'([^']*)'", cond, re.IGNORECASE)
    if m:
        col = _resolve_field(m.group(1))
        return f"{col} ILIKE %s", [f"%{m.group(2)}%"]

    # startswith
    m = re.match(r'(\w+)\s+startswith\s+"([^"]*)"', cond, re.IGNORECASE)
    if m:
        col = _resolve_field(m.group(1))
        return f"{col} ILIKE %s", [f"{m.group(2)}%"]

    # == with string
    m = re.match(r'(\w+)\s*==\s*"([^"]*)"', cond, re.IGNORECASE)
    if not m:
        m = re.match(r"(\w+)\s*==\s*'([^']*)'", cond, re.IGNORECASE)
    if m:
        col = _resolve_field(m.group(1))
        return f"{col} = %s", [m.group(2)]

    # != with string
    m = re.match(r'(\w+)\s*!=\s*"([^"]*)"', cond, re.IGNORECASE)
    if m:
        col = _resolve_field(m.group(1))
        return f"{col} != %s", [m.group(2)]

    # == with number
    m = re.match(r'(\w+)\s*==\s*(\d+)', cond, re.IGNORECASE)
    if m:
        col = _resolve_field(m.group(1))
        return f"{col} = %s", [int(m.group(2))]

    # != with number
    m = re.match(r'(\w+)\s*!=\s*(\d+)', cond, re.IGNORECASE)
    if m:
        col = _resolve_field(m.group(1))
        return f"{col} != %s", [int(m.group(2))]

    # > < >= <=
    m = re.match(r'(\w+)\s*(>=|<=|>|<)\s*(\d+)', cond, re.IGNORECASE)
    if m:
        col = _resolve_field(m.group(1))
        op  = m.group(2)
        return f"{col} {op} %s", [int(m.group(3))]

    raise KQLError(f"Could not parse condition: '{cond}'")


def _resolve_field(name):
    col = FIELD_MAP.get(name.lower())
    if not col:
        raise KQLError(f"Unknown field: '{name}'. Valid fields: {', '.join(FIELD_MAP.keys())}")
    return col

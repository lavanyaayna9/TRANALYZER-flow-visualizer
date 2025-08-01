# db_utils.py
import pandas as pd
import sqlite3
import uuid

def save_flows_to_sqlite(df, db_path="flows.db", table="flows"):
    session_id = str(uuid.uuid4())
    upload_time = pd.Timestamp.now().isoformat()
    df = df.copy()
    df["session_id"] = session_id
    df["upload_time"] = upload_time

    conn = sqlite3.connect(db_path)
    df.to_sql(table, conn, if_exists='append', index=False)
    conn.close()
    return session_id

def load_latest_flows(db_path="flows.db", table="flows"):
    conn = sqlite3.connect(db_path)
    result = conn.execute(
        f"SELECT session_id FROM {table} ORDER BY upload_time DESC LIMIT 1"
    ).fetchone()
    if not result:
        conn.close()
        return None
    latest_session = result[0]
    df = pd.read_sql_query(
        f"SELECT * FROM {table} WHERE session_id = ?", conn, params=(latest_session,)
    )
    conn.close()
    return df

def get_sessions(db_path="flows.db", table="flows", n=10):
    conn = sqlite3.connect(db_path)
    df = pd.read_sql(
        f"SELECT DISTINCT session_id, upload_time FROM {table} ORDER BY upload_time DESC LIMIT {n}", conn
    )
    conn.close()
    return df

def load_flows_by_session(session_id, db_path="flows.db", table="flows"):
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        f"SELECT * FROM {table} WHERE session_id = ?", conn, params=(session_id,)
    )
    conn.close()
    return df

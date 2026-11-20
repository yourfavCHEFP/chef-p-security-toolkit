# Injection (SQL, command, template, NoSQL, LDAP/XPath)
Signals: user input concatenated or f-string'd into a query/command/template; `shell=True`, `exec()`, `system()`.
## SQL
Use bound parameters, never string building.
- Python: `conn.execute("SELECT ... WHERE name = ?", (name,))` (sqlite); `cur.execute("... %s", (name,))` (psycopg); SQLAlchemy `text("... :n").bindparams(n=name)`.
- Node: `db.query("... WHERE id = $1", [id])`. Go: `db.Query("... WHERE id = $1", id)`. C#: `SqlParameter`/Dapper params. Java: `PreparedStatement`.
- Identifiers (table/column/ORDER BY) cannot be bound: allow-list them.
## Command execution
Avoid the shell. Pass an argv list: Python `subprocess.run([bin, arg], shell=False)`; Node `execFile`/`spawn` (not `exec`); Go `exec.Command(name, args...)`; C# `ProcessStartInfo.ArgumentList`. Allow-list the binary and validate arguments (`--` before user values where the tool supports it).
## Templates / NoSQL / LDAP
Never render user-controlled template source; keep autoescape on. MongoDB: reject non-string values where a string is expected (blocks `{"$ne": ...}`). LDAP/XPath: use the library's escaping/parameter API.
## Verify and test
verify.sh on the rule id; regression test with payloads like `' OR '1'='1` and `x; echo INJECTED` asserting literal handling. Pitfall: a test asserting "output lacks INJECTED" fails when the harmless echo prints the literal text; assert the exact expected output instead.

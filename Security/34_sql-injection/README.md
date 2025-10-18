# 34. SQL Injection

> **Abstract.** `database/sql` gives Go a structural defence against SQL injection: `db.QueryContext(ctx, query, args...)` delivers the query text and the arguments to the driver on separate channels, so a bound value is compared, never parsed. The defence evaporates the moment input reaches the *text* channel — `fmt.Sprintf`, `+`, or a query builder fed raw fragments. Three places push developers there because placeholders cannot express them: identifiers in `ORDER BY` or table names, variable-length `IN (...)` lists, and `LIKE` patterns whose wildcards are data. Each has a fix that keeps input out of the SQL text: an allowlist, generated placeholders, and wildcard escaping.

| | |
|---|---|
| Weaknesses | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) SQL Injection, [CWE-943](https://cwe.mitre.org/data/definitions/943.html) Improper Neutralization of Special Elements in Data Query Logic |
| Go packages | `database/sql`, `database/sql/driver` |
| Code | [`query.go`](query.go), [`driver_test.go`](driver_test.go) (recording driver), [`sqlinject_test.go`](sqlinject_test.go) |

## 1. Threat model

An HTTP API filters, sorts and searches a table based on query parameters. The attacker controls those parameters (and, for second-order injection, values previously stored in the database). Their goals: read other tables (`UNION`, blind boolean/time probes), bypass authentication (`' OR '1'='1`), modify data, or exhaust the database with expensive patterns.

## 2. What the standard library does

| Channel | Carries | Parsed as SQL? |
|---|---|---|
| `query string` | Statement text | Yes, by the database |
| `args ...any` | Values, converted by `driver.DefaultParameterConverter` or the driver's `NamedValueChecker` | No — sent as bind parameters, or escaped by the driver when it interpolates client-side |

`database/sql` itself never interpolates. It hands both channels to the driver (`driver.QueryerContext`, or `Prepare` + `Stmt.Query`). Drivers then either use the database's native parameter protocol (PostgreSQL extended query protocol, MySQL binary protocol) or, when explicitly configured — e.g. `interpolateParams=true` in go-sql-driver/mysql — escape values themselves. Placeholder syntax is driver-specific: `?` (MySQL, SQLite), `$1` (PostgreSQL), `@p1`/`@name` (SQL Server).

The test suite proves the separation with a small fake driver ([`driver_test.go`](driver_test.go)) that records exactly what `database/sql` delivers:

```
SELECT id, name FROM users WHERE name = 'x' OR '1'='1' []                 ← FindUserUnsafe
SELECT id, name FROM users WHERE name = ? ["x' OR '1'='1"]                ← FindUser
```

## 3. Insecure pattern

```go
q := fmt.Sprintf("SELECT id, name FROM users WHERE name = '%s'", name)       // FindUserUnsafe
q := "SELECT id, name FROM users ORDER BY " + column + " " + dir             // ListUsersUnsafe
```

The first is the textbook case. The second survives code review far more often, because `ORDER BY ?` is legal but sorts by a constant, so developers conclude identifiers "can't be parameterised" and concatenate. A sort column is a full expression position: `(CASE WHEN (SELECT substr(password,1,1) FROM admins)='a' THEN id ELSE name END)` turns the row order into a one-bit oracle (`TestListUsersUnsafeOrderByInjection`). The same holds for `GROUP BY`, column lists, table names, `LIMIT` in dialects that cannot bind it, and raw fragments passed to query builders and ORMs.

Escaping quotes by hand (`strings.ReplaceAll(s, "'", "''")`) is not a fix: it depends on the dialect, the connection character set and settings such as MySQL's `NO_BACKSLASH_ESCAPES`.

## 4. Secure pattern

| Need | Do | Code |
|---|---|---|
| Value in `WHERE`, `VALUES`, `SET` | Placeholder | `FindUser` |
| Sort column / direction | Map a public key to a fixed SQL fragment; reject unknown keys before any query | `ListUsers` |
| `IN (...)` list | Generate `?, ?, ?` for `len(ids)`, bind each ID, cap the count (bind-parameter limits: 65535 in PostgreSQL and MySQL, 32766 in SQLite ≥ 3.32), short-circuit the empty list | `FindByIDs`, `Placeholders` |
| `LIKE` search | Bind the pattern; escape `%`, `_` and the escape character, declare `ESCAPE '!'` | `SearchByPrefix`, `EscapeLike` |

```go
order, ok := sortKeys[sort]           // "-name" → "name DESC, id ASC"
if !ok { return nil, ErrBadInput }
s.query(ctx, "SELECT id, name FROM users ORDER BY "+order)
```

Concatenation remains, but only of constants chosen by the program. That is the rule to review against: **the query text may depend on input only through a lookup table or a count.** A non-backslash escape character for `LIKE` avoids the dialect split where `'\'` is a complete literal in PostgreSQL and SQLite but an unterminated one in MySQL.

## 5. Where the guarantee ends

- **Second-order injection.** A value stored safely and later concatenated into a report query or a stored procedure's dynamic SQL is still injection. The rule applies at every query, not at the input boundary.
- **Driver options.** go-sql-driver/mysql's `multiStatements=true` permits stacked queries (`; DROP TABLE`) for any injection that does exist; leave it off. Client-side interpolation is safe only as long as the driver knows the connection's character set.
- **ORMs and builders.** Methods that take raw strings (`Order`, `Select`, `Where("name = '" + x + "'")`, `Raw`) are concatenation with extra steps; see the GORM security notes.
- **Quoting identifiers** with a driver helper (e.g. pgx's `Identifier.Sanitize`) stops syntax breakout but still lets the client choose *any* column, including `password_hash`. An allowlist decides what is sortable.
- **Query-logic injection beyond SQL (CWE-943).** Decoding JSON into `map[string]any` and passing it as a MongoDB filter lets `{"password": {"$ne": ""}}` through. Decode into typed structs (chapter 35) and build filters from fields.
- **Denial of service.** Bound values can still be expensive: a leading `%` defeats indexes, huge `IN` lists and `OFFSET`s scan. Cap them, and set statement timeouts via `context`.
- **Errors.** Database error text echoed to clients helps an attacker map the schema (chapter 07).

## 6. Verification

```bash
go test -v ./Security/34_sql-injection/
```

| Test | Shows |
|---|---|
| `TestFindUserUnsafeInjectsIntoQueryText` | Payloads change the query's structure (string-literal skeleton) and travel with no args |
| `TestFindUserBindsValue` | Query text is constant for every input; the payload is the single bound arg |
| `TestListUsersUnsafeOrderByInjection` | A subquery reaches the `ORDER BY` clause |
| `TestListUsersAllowlist` | Known keys map to fixed SQL; unknown keys never reach the driver |
| `TestFindByIDs` | One placeholder per ID, typed args; empty and oversized lists send no query |
| `TestSearchByPrefixEscapesWildcards` | `%`, `_`, `!` are escaped inside the bound pattern |
| `ExampleStore_FindUserUnsafe` | What the driver receives in both cases |

## 7. Checklist

- [ ] No `fmt.Sprintf`, `+` or `strings.Builder` with request data in SQL text; grep for `Sprintf("SELECT`, `Sprintf("UPDATE`, `"WHERE " +`.
- [ ] Every dynamic identifier comes from a map or `switch` of constants.
- [ ] `IN` lists are generated placeholders with an upper bound.
- [ ] `LIKE` inputs are escaped and the `ESCAPE` character is declared.
- [ ] Driver DSNs do not enable multi-statement execution.
- [ ] ORM calls that accept raw SQL fragments are reviewed like string concatenation.
- [ ] Queries run with a `context` deadline.

## References

- Package [`database/sql`](https://pkg.go.dev/database/sql), [`database/sql/driver`](https://pkg.go.dev/database/sql/driver); Go documentation — [Avoiding SQL injection risk](https://go.dev/doc/database/sql-injection)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- go-sql-driver/mysql — [DSN parameters](https://github.com/go-sql-driver/mysql#parameters) (`interpolateParams`, `multiStatements`)
- SQLite — [Limits in SQLite](https://www.sqlite.org/limits.html) (`SQLITE_MAX_VARIABLE_NUMBER`)
- GORM — [Security](https://gorm.io/docs/security.html)

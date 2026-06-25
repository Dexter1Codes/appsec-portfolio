# SQL Injection

## 1. What it is

SQLi allows an attacker to interfere with the queries that an application makes to its database which makes them able to see the data that is not normally available. In most of the cases, the attacker can modify this data. Beyond reading, the attacker can often modify or delete data, and in some cases reach the underlying server or perform denial-of-service

In some cases, this modification access can lead to server level changes or other back-end infrastructure. It can also make them able to perform denial-of-service.

## 2. How it's exploited

### 2a. Retrieving hidden data (logic via the WHERE clause)

**Context:** input is concatenated into a `WHERE` clause that filters returned rows.

Consider a shop that loads a product category:

```
https://insecure-website.com/products?category=Gifts
```

The application likely runs something like `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`. The `released = 1` condition is a hidden filter: you don't see it, but you can infer it exists from the application's behaviour.

**Technique:**

| Payload | Effect |
|---|---|
| `Gifts'--` | Comments out everything after, killing trailing conditions (e.g. `released = 1`) → unreleased products appear |
| `Gifts' OR 1=1--` | Always-true condition → returns every row regardless of category |

**Why it works:** the input is parsed as SQL syntax, not as a string value. `--` begins a SQL comment, neutralising the rest of the query. `OR 1=1` injects a condition that is always true.

> **Caution:** `OR 1=1` is destructive if the same injection point reaches an `UPDATE` or `DELETE` elsewhere, an always-true `WHERE` there modifies or removes *every* row. Never fire it blindly on a real target.

### 2b. Authentication bypass (subverting login logic)

**Context:** a login query of the form `SELECT * FROM users WHERE username = 'X' AND password = 'Y'`.

**Technique:** submit `administrator'--` in the username field and leave the password blank. The query becomes:

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```

**Why it works:** the `--` comments out the entire password check, so authentication succeeds on the username alone.

> Works for any account whose username you know or can guess, no password required.


## 3. Real-world impact + CVSS

**Severity: High → Critical** (typical CVSS **7.5+**).

SQLi has driven some of the largest recorded data breaches. Impact includes credential and PII theft, payment-data exposure, unauthorised data modification and where the database account is over-privileged or stacked queries are possible, persistent back-doors, lateral movement, and denial of service.

## 4. How to detect it (tester's signals)

- A single quote `'` breaks the response: SQL errors, blank results, or output that differs from baseline.
- `ORDER BY n` with increasing `n` until an error reveals the column count.
- Conditional time-delay probes confirm **blind** injection points.
- Verbose DB error messages leaking schema, table names, or DBMS type/version.

## 5. How to fix it

**Root cause:** user input is concatenated into the query string, so the database parses attacker-supplied data as query structure.

**Primary fix: parameterized queries (prepared statements).** The query template is sent to the database *pre-compiled*, with placeholders for input. User input is then bound as **data** and can never alter the query's structure. This single mechanism defeats every variant (retrieving hidden data, auth bypass, UNION, blind, and second-order alike) because the code/data boundary is enforced by the database, not by string hygiene.

**Limit:** parameters bind *values* only: they cannot parameterise table names, column names, or `ORDER BY` direction. Where those must be dynamic, validate against an **allowlist** of permitted values.

**Defense-in-depth:** run the application on a **least-privilege database account**, so that even a successful injection cannot read or write beyond what that account strictly needs.

## 6. References

- PortSwigger Web Security Academy: SQL injection
- OWASP: SQL Injection Prevention Cheat Sheet

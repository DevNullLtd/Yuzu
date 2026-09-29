# Scope Engine

The scope engine is Yuzu's device targeting system. It evaluates expression strings against agent attributes to determine which devices an instruction, schedule, or management group applies to. The engine uses a recursive-descent parser that supports 10 comparison operators, 3 extended operators/functions (`EXISTS`, `LEN()`, `STARTSWITH()`), boolean combinators, wildcard matching, and parenthesized grouping.

---

## Table of Contents

1. [Where Scope Expressions Are Used](#1-where-scope-expressions-are-used)
2. [Expression Syntax](#2-expression-syntax)
3. [Comparison Operators](#3-comparison-operators)
4. [Boolean Combinators](#4-boolean-combinators)
5. [Available Attributes](#5-available-attributes)
6. [Tag Attributes](#6-tag-attributes)
6a. [Custom Property Attributes](#6a-custom-property-attributes)
7. [Wildcard Matching](#7-wildcard-matching)
8. [Operator Precedence and Grouping](#8-operator-precedence-and-grouping)
9. [Examples](#9-examples)
10. [REST API](#10-rest-api)
11. [Limits and Constraints](#11-limits-and-constraints)
12. [Extended Operators Reference](#12-extended-operators-reference)

---

## 1. Where Scope Expressions Are Used

Scope expressions appear in three contexts:

| Context | Where | Purpose |
|---|---|---|
| **Instruction execution** | `scope_expression` field on an execution | Determines which agents receive the command at dispatch time. |
| **Management group membership** | `scope_expression` on a dynamic management group | Devices matching the expression are automatically added to the group. |
| **Instruction scheduling** | `scope_expression` on a schedule | Evaluated at each scheduled dispatch to determine the target set. New devices enrolled since the schedule was created are automatically included. |

Because scope expressions are evaluated at dispatch time (not at authoring time), the target set is always current.

---

## 2. Expression Syntax

### Grammar

```
expr       ::= or_expr
or_expr    ::= and_expr ('OR' and_expr)*
and_expr   ::= not_expr ('AND' not_expr)*
not_expr   ::= 'NOT' not_expr | primary
primary    ::= '(' expr ')' | exists_expr | len_expr | startswith_expr | condition
condition  ::= IDENT op value
op         ::= '==' | '!=' | 'LIKE' | 'MATCHES' | '<' | '>' | '<=' | '>=' | 'IN' | 'CONTAINS'
value      ::= QUOTED_STRING | '(' value_list ')' | IDENT
value_list ::= value (',' value)*

exists_expr     ::= 'EXISTS' IDENT
len_expr        ::= 'LEN' '(' IDENT ')' op value
startswith_expr ::= 'STARTSWITH' '(' IDENT ',' value ')'
```

### Quick Start

The simplest expression is a single condition:

```
ostype == "windows"
```

Combine conditions with `AND`, `OR`, and `NOT`:

```
ostype == "windows" AND tag:environment == "Production"
```

Group with parentheses to control evaluation order:

```
(ostype == "windows" OR ostype == "linux") AND tag:datacenter == "us-east-1"
```

All keywords (`AND`, `OR`, `NOT`, `LIKE`, `IN`, `CONTAINS`, `MATCHES`, `EXISTS`, `LEN`, `STARTSWITH`) are case-insensitive. You can write `and`, `AND`, or `And`.

---

## 3. Comparison Operators

Ten binary comparison operators are available, plus 3 extended operators/functions.

### Binary Comparison Operators

| Operator | Description | Example |
|---|---|---|
| `==` | Equality (case-insensitive) | `ostype == "windows"` |
| `!=` | Inequality (case-insensitive) | `ostype != "linux"` |
| `LIKE` | Wildcard glob matching | `hostname LIKE "web-*"` |
| `MATCHES` | Regular expression matching (case-insensitive) | `hostname MATCHES "^web-\d+$"` |
| `<` | Less than (numeric comparison) | `agent_version < "1.0.0"` |
| `>` | Greater than (numeric comparison) | `agent_version > "0.8.0"` |
| `<=` | Less than or equal | `agent_version <= "0.9.0"` |
| `>=` | Greater than or equal | `agent_version >= "0.9.0"` |
| `IN` | Membership in a value list | `arch IN ("x86_64", "aarch64")` |
| `CONTAINS` | Case-insensitive substring search | `hostname CONTAINS "prod"` |

### Extended Operators

| Operator | Description | Example |
|---|---|---|
| `EXISTS` | True if attribute resolves to a non-empty string (unary) | `EXISTS tag:environment` |
| `LEN()` | Compares the string length of an attribute value | `LEN(hostname) > 5` |
| `STARTSWITH()` | Case-insensitive prefix check | `STARTSWITH(hostname, "web-")` |

### Comparison Behavior

- **String comparisons** (`==`, `!=`, `LIKE`, `CONTAINS`, `MATCHES`) are case-insensitive.
- **Numeric comparisons** (`<`, `>`, `<=`, `>=`) attempt to parse both sides as numbers using `std::from_chars` with a fallback to `std::stod` for floating-point values and Apple libc++ compatibility. If either side is not a valid number, the comparison falls back to lexicographic string comparison.
- **IN operator** accepts a comma-separated list of quoted strings in parentheses: `arch IN ("x86_64", "aarch64")`.
- **MATCHES operator** uses ECMAScript regex syntax. Invalid regex patterns evaluate to false rather than raising an error.
- **EXISTS operator** is unary -- it takes an attribute name with no comparison value. Returns true if the attribute resolves to a non-empty string.
- **LEN() function** converts the attribute's string length to a number and compares it. Supports `==`, `!=`, `<`, `>`, `<=`, `>=`.
- **STARTSWITH() function** is equivalent to `LIKE "prefix*"` but more explicit about intent. Case-insensitive.

---

## 4. Boolean Combinators

Three combinators join conditions into complex expressions.

| Combinator | Description | Example |
|---|---|---|
| `AND` | Both sides must be true | `ostype == "windows" AND tag:env == "prod"` |
| `OR` | Either side must be true | `hostname LIKE "web-*" OR hostname LIKE "api-*"` |
| `NOT` | Negates the following expression | `NOT tag:quarantined == "true"` |

### Precedence (highest to lowest)

1. `NOT` (unary, binds tightest)
2. `AND`
3. `OR` (binds loosest)

This means `A OR B AND NOT C` is parsed as `A OR (B AND (NOT C))`. Use parentheses to override:

```
(A OR B) AND NOT C
```

---

## 5. Available Attributes

The scope engine resolves attributes through an `AttributeResolver` callback. The following attributes are available for all enrolled agents.

### Built-in Attributes

| Attribute | Description | Example Values |
|---|---|---|
| `ostype` | Operating system type | `"windows"`, `"linux"`, `"darwin"` |
| `hostname` | Machine hostname | `"web-prod-01"`, `"DB-STAGING-03"` |
| `arch` | CPU architecture | `"x86_64"`, `"aarch64"`, `"arm64"` |
| `agent_version` | Agent software version | `"0.9.0"`, `"1.2.3"` |

### Tag Attributes

Any device tag can be referenced using the `tag:` prefix. See [Section 6](#6-tag-attributes) for details.

### Custom Property Attributes

Custom properties set via the Custom Properties API can be referenced in scope expressions using the `props.` prefix. See [Section 6a](#6a-custom-property-attributes) for details.

---

## 6. Tag Attributes

Device tags are key-value pairs assigned to agents. Tags can be set by the agent itself (e.g. from hardware discovery), set server-side by an operator, or set via the API. The scope engine can query any tag using the `tag:<key>` syntax.

> **Precedence when a tag has more than one source.** A `tag:<key>` atom resolves the
> persistent tag store first; a connected agent's own live self-reported value answers
> only when the store has no row at all for that key. `service` (used in the examples
> below) is special-cased further — it never answers from a live agent self-report at
> all, even as a fallback. See `docs/asset-tagging-guide.md`'s "Tag source precedence (write
> time)" and "Tag source precedence (read time, scope-DSL, #3295)" blockquotes for the full
> write-time and read-time rules, respectively.

### Syntax

```
tag:<key> <operator> <value>
```

### Examples

```
tag:environment == "Production"
tag:service == "payments"
tag:location LIKE "us-*"
tag:team CONTAINS "platform"
tag:tier IN ("gold", "silver")
```

### Tag Validation

Tags are subject to the following constraints:
- **Key**: maximum 64 characters.
- **Value**: maximum 448 bytes.
- **Source**: `"agent"`, `"server"`, or `"api"` -- indicates where the tag was set.

### Common Tag Patterns

| Tag Key | Purpose | Example Values |
|---|---|---|
| `environment` | Deployment stage | `"Production"`, `"Staging"`, `"Dev"` |
| `location` | Data center or region | `"us-east-1"`, `"eu-west-2"` |
| `team` | Owning team | `"platform-engineering"`, `"sre"` |
| `service` | Application or service name | `"payments"`, `"auth"`, `"api-gateway"` |
| `tier` | Service tier | `"gold"`, `"silver"`, `"bronze"` |
| `os_family` | OS family (set by agent) | `"debian"`, `"rhel"`, `"windows-server"` |

---

## 6a. Custom Property Attributes

Custom properties are operator-defined key-value pairs on agents, managed via the REST API (see `PUT /api/agents/:id/properties/:key`). Unlike tags, properties can have schemas that enforce type and allowed values.

### Syntax

Custom properties are referenced in scope expressions using the `props.` prefix:

```
props.<key> <operator> <value>
```

### Examples

```
props.department == "Engineering"
props.cost_center LIKE "CC-*"
props.department == "Engineering" AND os == "windows"
props.region IN ("us-east", "us-west", "eu-west")
NOT props.decommissioned == "true"
EXISTS props.department
```

### Combined with Tags and Built-in Attributes

Custom properties work alongside tags and built-in attributes in any expression:

```
ostype == "windows" AND props.department == "Engineering" AND tag:environment == "Production"
```

### Custom Properties vs. Tags

| | Tags | Custom Properties |
|---|---|---|
| **Prefix** | `tag:` | `props.` |
| **Set by** | Agent, server, or API | API only (operator-managed) |
| **Schema enforcement** | Category-based (4 categories) | Property schemas (type, allowed values, required) |
| **Primary use** | Device classification and targeting | Organizational metadata and compliance attributes |

---

## 7. Wildcard Matching

The `LIKE` operator supports glob-style pattern matching.

### Wildcards

| Character | Matches |
|---|---|
| `*` | Any sequence of characters (including empty) |
| `?` | Any single character |

### Examples

| Expression | Matches | Does Not Match |
|---|---|---|
| `hostname LIKE "web-*"` | `web-01`, `web-prod-us` | `api-01`, `db-web` |
| `hostname LIKE "web-??"` | `web-01`, `web-ab` | `web-001`, `web-1` |
| `hostname LIKE "*-prod-*"` | `web-prod-01`, `api-prod-us` | `web-staging-01` |
| `hostname LIKE "db-*"` | `db-01`, `db-primary` | `web-db-01` |

Matching is case-insensitive. `hostname LIKE "WEB-*"` matches `web-01`.

---

## 8. Operator Precedence and Grouping

### Default Precedence

Without parentheses, expressions bind in this order:

1. `NOT` (tightest)
2. `AND`
3. `OR` (loosest)

### Evaluation Examples

| Expression | Parsed As |
|---|---|
| `A OR B AND C` | `A OR (B AND C)` |
| `NOT A AND B` | `(NOT A) AND B` |
| `A OR B AND NOT C` | `A OR (B AND (NOT C))` |
| `NOT A OR NOT B` | `(NOT A) OR (NOT B)` |

### Using Parentheses

Parentheses override default precedence:

```
# Without parentheses: targets Windows, OR (Linux AND Production)
ostype == "windows" OR ostype == "linux" AND tag:environment == "Production"

# With parentheses: targets (Windows OR Linux), AND Production
(ostype == "windows" OR ostype == "linux") AND tag:environment == "Production"
```

Always use parentheses when combining `AND` and `OR` to make intent explicit.

---

## 9. Examples

### Basic Targeting

```bash
# All Windows devices
ostype == "windows"

# All non-Linux devices
ostype != "linux"

# Devices with a specific hostname
hostname == "web-prod-01"
```

### Tag-Based Targeting

```bash
# Production payment servers
tag:environment == "Production" AND tag:service == "payments"

# Any non-development device
NOT tag:environment == "Dev"

# Gold or silver tier
tag:tier IN ("gold", "silver")
```

### Hostname Patterns

```bash
# Web servers or API servers
hostname LIKE "web-*" OR hostname LIKE "api-*"

# Any server with "prod" in the name
hostname CONTAINS "prod"

# Servers matching a naming convention
hostname LIKE "??-prod-*"
```

### Multi-Platform Targeting

```bash
# Windows and Linux, but not macOS
ostype IN ("windows", "linux")

# All platforms in a specific region
ostype IN ("windows", "linux", "darwin") AND tag:location == "us-east-1"
```

### Complex Expressions

```bash
# Production Windows servers OR any server tagged critical
(ostype == "windows" AND tag:environment == "Production") OR tag:priority == "critical"

# Non-dev Linux servers in US data centers
ostype == "linux" AND NOT tag:environment == "Dev" AND tag:location LIKE "us-*"

# Servers above a minimum agent version in production
tag:environment == "Production" AND agent_version >= "0.9.0"
```

### Scope Expression in an Instruction Execution (curl)

```bash
# Execute a service inspection on production Windows servers
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/executions \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "crossplatform.service.inspect",
    "scope_expression": "ostype == \"windows\" AND tag:environment == \"Production\"",
    "parameter_values": "{\"serviceName\": \"Spooler\"}"
  }'
```

### Scope Expression in a Schedule

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/schedules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Hourly Linux process sweep",
    "definition_id": "crossplatform.process.list",
    "frequency_type": "interval",
    "interval_minutes": 60,
    "scope_expression": "ostype == \"linux\" AND tag:environment IN (\"Production\", \"Staging\")",
    "enabled": true
  }'
```

---

## 10. REST API

### Validate an Expression

```
POST /api/scope/validate
```

Parses the expression and returns success or a descriptive parse error. Does not evaluate against any agents.

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/scope/validate \
  -H "Content-Type: application/json" \
  -d '{"expression": "ostype == \"windows\" AND tag:environment == \"Production\""}'
```

**Success response:**

```json
{
  "valid": true
}
```

**Error response (malformed expression):**

```json
{
  "valid": false,
  "error": "unexpected token at position 23: expected operator"
}
```

### Estimate Target Count

```
POST /api/scope/estimate
```

Evaluates the expression against all enrolled agents and returns the count of matching devices and the total number of enrolled agents. Use this before executing instructions on large fleets to verify targeting.

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/scope/estimate \
  -H "Content-Type: application/json" \
  -d '{"expression": "ostype == \"windows\" AND tag:environment == \"Production\""}'
```

**Response:**

```json
{
  "matched": 142,
  "total": 500
}
```

Use the estimate endpoint to:
- **Preview targeting** before dispatching a definition.
- **Verify tag assignments** by checking which devices match tag-based expressions.
- **Test complex expressions** interactively before embedding them in schedules or management groups.

---

## 11. Limits and Constraints

| Constraint | Value | Description |
|---|---|---|
| Maximum nesting depth | 10 | Parenthesized expressions cannot nest deeper than 10 levels. Prevents stack overflow on pathological input. |
| Case sensitivity | Insensitive | All string comparisons and keyword matching are case-insensitive. |
| Tag key length | 64 chars | Maximum length of a tag key. |
| Tag value length | 448 bytes | Maximum length of a tag value. |
| Expression length | No hard limit | Expressions are bounded practically by nesting depth and readability. |

### Error Messages

The parser returns descriptive error messages with character positions:

| Scenario | Example Error |
|---|---|
| Missing operator | `"expected operator at position 15, got '...'"` |
| Unterminated string | `"unterminated string"` |
| Nesting too deep | `"maximum nesting depth exceeded"` |
| Unknown operator | `"expected operator at position 12, got 'EQUALS'"` |
| Empty expression | `"empty expression"` |
| Unmatched parenthesis | `"expected ')' at position 20, got '...'"` |
| Missing LEN() paren | `"expected '(' after LEN at position 4"` |
| Missing STARTSWITH() comma | `"expected ',' in STARTSWITH() at position 22"` |

---

## 12. Extended Operators Reference

The following operators and functions are fully implemented and available for use. They are documented in the operator table in [Section 3](#3-comparison-operators) and included here with additional usage detail.

### MATCHES (regex)

Full regular expression matching (ECMAScript syntax, case-insensitive) for complex hostname or version patterns:

```
hostname MATCHES "^web-\d{2,3}$"
```

If the regex is invalid, the expression evaluates to `false` rather than producing an error.

### EXISTS (tag presence)

Check whether a tag key exists on a device (resolves to a non-empty string):

```
EXISTS tag:environment
```

Useful when you want to target "all devices that have been tagged" without caring about the specific value. An attribute set to an empty string is treated as absent.

### LEN() (string length)

Compare the length of an attribute or tag value. Supports `==`, `!=`, `<`, `>`, `<=`, `>=`:

```
LEN(tag:description) > 5
LEN(hostname) == 11
```

### STARTSWITH() (prefix check)

Check whether an attribute value starts with a given prefix (case-insensitive). More readable than `LIKE` for simple prefix matching:

```
STARTSWITH(hostname, "web-")
```

Equivalent to `hostname LIKE "web-*"` but more explicit about intent.

### Combining Extended Operators

Extended operators can be freely combined with standard operators and boolean combinators:

```
EXISTS tag:env AND hostname MATCHES "^web-" AND LEN(tag:env) > 3
STARTSWITH(hostname, "web-") OR hostname MATCHES "^db-replica-\d+$"
```

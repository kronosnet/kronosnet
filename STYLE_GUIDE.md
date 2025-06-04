# Kronosnet Style Guide

This document outlines the coding style and conventions to be followed when contributing to the kronosnet project.

## General Principles

* Clarity: Code should be easy to read and understand.
* Consistency: Follow the established style throughout the codebase.
* Simplicity: Prefer simple solutions over complex ones.

## C Language Style

### Minimum Supported C Dialect
All C code should conform to the C99 standard. Do not use compiler-specific extensions unless absolutely necessary and properly guarded with preprocessor directives.

### Indentation
* Use Tabs for indentation. Do not use spaces.

### Curly Braces
* Place the opening curly brace on the same line as control flow statements (e.g., `if`, `for`, `while`). For function definitions, the opening curly brace should be on the next line.
* Always use curly braces for `if`, `for`, `while`, and `do-while` statements, even if the body is a single line.

**Example:**
```c
if (condition) {
	do_something();
}

for (int i = 0; i < 10; i++) {
	process_item(i);
}
```

### Variable Declaration
* Declare variables at the beginning of their scope (e.g., at the start of a function or a block).

**Example:**
```c
void my_function()
{
	int count;
	char *name;

	// ... function logic ...
}
```

### Naming Conventions
* Use `snake_case` for variable names and function names. (e.g., `user_input`, `calculate_total_sum`).
* Public API elements (functions, structs, typedefs, etc.) must be prefixed according to the library they belong to. Use `knet_` for items in the Kronosnet core library and `nozzle_` for items in the Nozzle library.
* Public enums and defines (macros) must be prefixed with `KNET_` or `NOZZLE_` (all uppercase), followed by an uppercase `SNAKE_CASE` name that describes their purpose (e.g., `KNET_MAX_CLIENTS`, `NOZZLE_BUFFER_SIZE_DEFAULT`).
* Internal (non-public) functions, structs, enums, unions, and macros should have names that are descriptive, clearly indicating their purpose and the subsystem they belong to. Generally, no specific prefix is mandated for these internal elements.
* Functions that are designed to be shared and called from multiple different threads must be prefixed with a single underscore (`_`). For example: `_shared_resource_access()`.

## Line Length
Preferred maximum line length is 120 characters.

While this is a preference, it is understood that this limit may be exceeded in certain situations for better readability, such as with deeply nested structures or long string literals.

## Comments
* Use `//` for single-line comments.
* Use `/* ... */` for multi-line comments.
* Write clear and concise comments to explain non-obvious code.

## Best Practices
* API Changes Require Tests: Any modification to an internal or external API must be accompanied by new or updated tests in the project's test suite. These tests must validate the behavior of the changed API.

---
## Copyright

Copyright (C) 2025 Red Hat, Inc.  All rights reserved.

Author: Jules <AI Agent>

This software licensed under GPL-2.0+

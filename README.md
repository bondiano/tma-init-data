# TMA Init Data Rust

The crate provides utilities to work with Telegram Mini Apps init data.

[![Crates.io](https://img.shields.io/crates/v/tma-init-data)](https://crates.io/crates/tma-init-data)
[![codecov](https://codecov.io/gh/bondiano/tma-init-data/graph/badge.svg?token=wnjlCIKacN)](https://codecov.io/gh/bondiano/tma-init-data)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tma-init-data = "0.1"
```

## Available functions

- `parse` - allow to parse string with init data into `InitData` struct.
- `validate` - validates passed init data.
- `sign` - signs hashmap with the passed token.
- `sign_query_string` - signs query string with the passed token.

Implementation was taken from [init-data-golang](https://github.com/Telegram-Mini-Apps/init-data-golang/tree/master).

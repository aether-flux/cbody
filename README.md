# cbody

A multi-profile LSM security module enforcer built in Rust and eBPF.

---

# What is cbody?

`cbody` is a profile-driven Linux Security Module (LSM) daemon written in Rust. It leverages eBPF with the `aya` library to enforce fine-grained binary execution, network, and file access policies.

## What is LSM?

LSM stands for Linux Security Modules. It provides hooks for eBPF programs to attach to, for purposes like telemetry and restrictions (which `cbody` mainly does). It provides many hooks, of which I have used the following:

- `lsm/bprm_check_security` / `#[lsm(hook = "bprm_check_security")]`: Fires whenever a file is executed. Used to block execution of binaries and other executables which can be harmful if unrestricted.
- `lsm/socket_connect` / `#[lsm(hook = "socket_connect")]`: Fires whenever a socket connection request is made. Used to detect and block restricted ports.
- `lsm/file_open` / `#[lsm(hook = "file_open")]`: Fires whenever any file (including `pty`s and `fd`s) are opened/accessed. Used to restrict access to `readonly` (no writing/modifying allowed) or `noaccess` (neither read nor write allowed).

To view the full list of LSM hooks, refer to [include/linux/lsm_hook_defs.h](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h).

---

# Features

Even in v0.1 release, `cbody` provides the following features:

- A `config.toml` to define default actions and rules, and profile-specific rules.
- Choose whether to `deny` (only deny the restricted actions without logs), `log` (only logs restricted actions but doesn't block them), or [1]`deny_and_log` (deny restricted actions as well as log them).
- Set default rules that apply for all users (deny executions, readonly/noaccess files, block ports).
- Create profiles with different names which apply to specific users (UIDs).

Upcoming features to be arrived by v1:

- Live-reloading daemon when config file is modified.
- A CLI to read, control, and manage the daemon without restarting it or manually handling config files.
- Automatically create systemd service for the daemon.
- Probably more stuff...

[1] Any string other than 'deny' and 'log' will have the same effect as 'deny_and_log'. 'deny_and_log' is only a recommended string to understand what the value does. For more information, refer to [CONFIG.md](./CONFIG.md).

---

# Configuring `cbody`

A full guide for writing a `config.toml`, along with a sample config, is at [CONFIG.md](./CONFIG.md).

---

# Pre-requisites

- `cbody` uses the `aya` framework for eBPF development, so the [pre-requisites of `aya`](https://aya-rs.dev/book/start/development.html) must be satisfied.
- Another helpful tool will be the [`aya-tool`](https://aya-rs.dev/book/aya/aya-tool.html).
- To view a basic example eBPF LSM code with `aya`, refer to their official [example documentation](https://aya-rs.dev/book/programs/lsm.html).

# Installation

Working on it. Will be available soon.

# Run it yourself

```sh
# Clone the repository
git clone https://github.com/aether-flux/cbody
cd cbody

# Run the daemon (removing RUST_LOG=info will remove the logs)
RUST_LOG=info sudo -E $(which cargo) run --bin cbody-daemon
```

---

# License

GPL 3.0

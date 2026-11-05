# The Config

It's not as dramatic as I made the heading sound. The config file of `cbody` is fairly straightforward.

### Sample Config

If you just want a sample config file to get started without any hassles, use this (read the comments for editing fields as needed):

```toml
[settings]
# (required) action specifies what cbody will do for a restricted action
action = "deny" # Options: "deny", "log", "deny_and_log"

# Default rules that apply for every user (UID)
[default]
# (optional) deny_exec contains a list of files that are restricted from being executed
deny_exec = [
    "/usr/bin/ssh",
    "/usr/bin/curl"
]
# (optional) readonly contains a list of files that can only be read but not written to
readonly = [
    "/tmp/cbody_test_readonly.txt",
]
# (optional) noaccess contains a list of files that can be neither read nor written to
noaccess = [
    "/tmp/cbody_test_noaccess.txt",
]
# (optional) block_outbound_ports contains a list of restricted ports
block_outbound_ports = [4444, 6666, 1337]

# Profile with name 'standard-users', applicable to UIDs 1000 and 1001
[profiles.standard-users]
# (required) uids contains the list of targeted UIDs
uids = [1000, 1001]
deny_exec = [
    "/usr/bin/pipes.sh",
]

# Profile with name 'standard-users', applicable to UIDs 33 and 48
[profiles.service-accounts]
uids = [33, 48]
deny_exec = [
    "/usr/sbin/nginx"
]
```

---

# Sections

Now for a detailed look, let's go through the entire structure one section at a time.

## `[settings]`

### `action` (String, required)

This field determines what `cbody` does when a restricted action takes place. It has three values:

- `deny`: Denies/blocks the restricted action from happening. Does not log the activity.
- `log`: Logs the restricted action that occurred, but does not block it.
- `deny_and_log`: Denies the restricted action from happening as well as logs the activity to the daemon.
- **Any other value**: Acts the same as `deny_and_log`.

## `[default]`

### `deny_exec` (Array[String], optional)

- This field is an array of strings, where each string is a path to an executable file.
- Files specified in this array are not allowed (restricted) to be executed.
- For example, shell scripts (`script.sh`), commands (`curl` - `/usr/bin/curl`), etc.

### `readonly` (Array[String], optional)

- This field is an array of strings, where each string is a path to a file.
- Files specified in this array are allowed to be read/accessed, but not allowed to be written/modified.
- For example, system configurations that can be viewed but modifications can be fatal.

### `noaccess` (Array[String], optional)

- This field is an array of strings, where each string is a path to a file.
- Files specified in this array are allowed to be neither read/accessed nor written/modified.
- For example, files which may contain vulnerable data.

### `block_outbound_ports` (Array[unsigned integer], optional)

- This field is an array of unsigned integers, where each number is a port number.
- Ports specified in this array are not allowed to be connected to or reached (i.e. used as a destination port).
- For example, common reverse shell ports.

## `[profiles.profile-name]`

## `deny_exec` (Array[String], optional)

- This field is an array of strings, where each string is a path to an executable file.
- Files specified in this array are not allowed (restricted) to be executed.
- For example, shell scripts (`script.sh`), commands (`curl` - `/usr/bin/curl`), etc.

### `readonly` (Array[String], optional)

- This field is an array of strings, where each string is a path to a file.
- Files specified in this array are allowed to be read/accessed, but not allowed to be written/modified.
- For example, system configurations that can be viewed but modifications can be fatal.

### `noaccess` (Array[String], optional)

- This field is an array of strings, where each string is a path to a file.
- Files specified in this array are allowed to be neither read/accessed nor written/modified.
- For example, files which may contain vulnerable data.

### `block_outbound_ports` (Array[unsigned integer], optional)

- This field is an array of unsigned integers, where each number is a port number.
- Ports specified in this array are not allowed to be connected to or reached (i.e. used as a destination port).
- For example, common reverse shell ports.

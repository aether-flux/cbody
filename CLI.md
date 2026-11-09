# The CLI

Added in v0.1.2, the CLI `cbody` is a really efficient way to manage the config properties and the daemon service without manually handle configuration files. The full documentation of all CLI commands is described below.

> NOTE: The CLI must be run as sudo/root, since services, logs, and config files, all require permissions to be accessed.

# Commands

## Init (`cbody init`)

- Creates a new default config file at the correct location (`/etc/cbody/config.toml`). The contents of the default config can be found at [CONFIG.md](./CONFIG.md).
- If a config file is already present at the location, you can choose whether to overwrite it with the default config or leave it be.

#### Usage

```sh
sudo cbody init
```

## Check (`cbody check`)

- Validates the location and structure of the config file.

#### Usage

```sh
sudo cbody check

# Or, run it without sudo, since this command doesn't need any write permissions
cbody check
```

## Enable_Service (`cbody enable-service`)

- Validates config file and the daemon binary (`/usr/bin/cbodyd`).
- If valid, creates a systemd service file and prepares the daemon service.
- You can choose whether to run the next commands directly from this command (`sudo systemctl daemon-reload` and `sudo systemctl enable --now cbody`).

#### Usage

```sh
sudo cbody enable-service
```

## Get (`cbody get`)

- Get the value(s) of properties defined in the config file.
- Uses dot notation to get the property name.
- For example, to view all files in the readonly array of profile 'restricted', the notation would be `profile.restricted.readonly`.
- Passing '_' as the property name would show all the properties in the config file in a readable format.

#### Usage

```sh
sudo cbody get exemptions.uids

# Or, run it without sudo, since this command doesn't need any write permissions
cbody get exemptions.uids

# View all properties of the config file
cbody get _
```

## Set (`cbody set`)

- Like it sounds, this can set the value of properties in the config file.
- The syntax is `cbody set <property> <value>`. `property` uses the same dot notation as `get`.
- For properties with a single value (like a string or number), the `value` would be just that value (eg, `cbody set settings.action deny`).
- For properties with multiple values (like arrays), the `value` would have all the values to be set in the array, separated by commas (eg, `cbody set exemptions.uids 0,1,1000`).
- This command overwrites any existing value in the config. For example, if `exemptions.uids` was currently `[1000, 1001]`, running `cbody set exemptions.uids 0,1,2` would make this value `[0, 1, 2]`, completely discarding the old value.

#### Usage

```sh
sudo cbody set default.exec "/usr/bin/nc,/usr/bin/curl"
sudo cbody set settings.action log
```

## Add (`cbody add`)

- Similar to `set`, this can also set the value of properties in the config file.
- The syntax is `cbody add <property> <value>`. `property` uses the same dot notation as `get`.
- For properties with a single value (like a string or number), the `value` would be just that value (eg, `cbody set settings.action deny`).
- For properties with multiple values (like arrays), the `value` would have all the values to be set in the array, separated by commas (eg, `cbody set exemptions.uids 0,1,1000`).
- This command does not overwrite existing values in the config. For example, if `exemptions.uids` was currently `[1000, 1001]`, running `cbody set exemptions.uids 0,1,2` would make this value `[1000, 1001, 0, 1, 2]`, appending to the old value.

#### Usage

```sh
sudo cbody add profile.restricted.readonly "/etc/sddm.conf.d/theme.conf,/etc/os-release"
```

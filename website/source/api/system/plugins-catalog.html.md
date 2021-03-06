---
layout: "api"
page_title: "/sys/plugins/catalog - HTTP API"
sidebar_current: "docs-http-system-plugins-catalog"
description: |-
  The `/sys/plugins/catalog` endpoint is used to manage plugins.
---

# `/sys/plugins/catalog`

The `/sys/plugins/catalog` endpoint is used to list, register, update, and
remove plugins in Vault's catalog. Plugins must be registered before use, and
once registered backends can use the plugin by querying the catalog.

## List Plugins

This endpoint lists the plugins in the catalog.

| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `LIST`   | `/sys/plugins/catalog`      | `200 application/json`  |

### Sample Request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request LIST
    http://127.0.0.1:8200/v1/sys/plugins/catalog
```

### Sample Response

```javascript
{
    "data": {
        "keys": [
            "cassandra-database-plugin",
            "mssql-database-plugin",
            "mysql-database-plugin",
            "postgresql-database-plugin"
        ]
    }
}
```

## Register Plugin

This endpoint registers a new plugin, or updates an existing one with the
supplied name.

- **`sudo` required** – This endpoint requires `sudo` capability in addition to
  any path-specific capabilities.

| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `PUT`    | `/sys/plugins/catalog/:name` | `204 (empty body)`     |

### Parameters

- `name` `(string: <required>)` – Specifies the name for this plugin. The name
  is what is used to look up plugins in the catalog. This is part of the request
  URL.

- `sha256` `(string: <required>)` – This is the SHA256 sum of the plugin's
  binary. Before a plugin is run it's SHA will be checked against this value, if
  they do not match the plugin can not be run.

- `command` `(string: <required>)` – Specifies the command used to execute the
  plugin. This is relative to the plugin directory. e.g. `"myplugin"`.

- `args` `(array: [])` – Specifies the arguments used to execute the plugin. If
  the arguments are provided here, the `command` parameter should only contain
  the named program. e.g. `"--my_flag=1"`.

- `env` `(array: [])` – Specifies the environment variables used during the
  execution of the plugin. Each entry is of the form "key=value". e.g
  `"FOO=BAR"`.

### Sample Payload

```json
{
  "sha_256": "d130b9a0fbfddef9709d8ff92e5e6053ccd246b78632fc03b8548457026961e9",
  "command": "mysql-database-plugin"
}
```

### Sample Request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request PUT \
    --data @payload.json \
    http://127.0.0.1:8200/v1/sys/plugins/catalog/example-plugin
```

## Read Plugin

This endpoint returns the configuration data for the plugin with the given name.

- **`sudo` required** – This endpoint requires `sudo` capability in addition to
  any path-specific capabilities.

| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `GET`    | `/sys/plugins/catalog/:name` | `200 application/json` |

### Parameters

- `name` `(string: <required>)` – Specifies the name of the plugin to retrieve.
  This is part of the request URL.

### Sample Request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request GET \
    http://127.0.0.1:8200/v1/sys/plugins/catalog/example-plugin
```

### Sample Response

```javascript
{
	"data": {
		"args": [],
		"builtin": false,
		"command": "/tmp/vault-plugins/mysql-database-plugin",
		"name": "example-plugin",
		"sha256": "0TC5oPv93vlwnY/5Ll5gU8zSRreGMvwDuFSEVwJpYek="
	}
}
```
## Remove Plugin from Catalog

This endpoint removes the plugin with the given name.

- **`sudo` required** – This endpoint requires `sudo` capability in addition to
  any path-specific capabilities.

| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `DELETE` | `/sys/plugins/catalog/:name` | `204 (empty body)`     |

### Parameters

- `name` `(string: <required>)` – Specifies the name of the plugin to delete.
  This is part of the request URL.

### Sample Request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request DELETE \
    http://127.0.0.1:8200/v1/sys/plugins/catalog/example-plugin
```

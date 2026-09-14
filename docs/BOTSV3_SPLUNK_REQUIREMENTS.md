# BOTS v3 Splunk Runtime Requirements

Provide:

- Operating system and version
- Splunk Enterprise version, if already installed
- Deployment type: local, VM, Docker, or remote
- RAM, CPU, and free storage
- Whether required BOTS apps/add-ons may be installed

Do not send passwords or tokens in chat. Credentials must be supplied locally through environment variables or a `.env` file excluded from version control.

## Validation searches

```spl
index=botsv3 earliest=0 | stats count
```

Expected active index count from bucket metadata: `2,030,269` events. The scenario-telemetry count after excluding two administrative content-import events is `2,030,267`.

```spl
index=botsv3 earliest=0 | stats count min(_time) as earliest max(_time) as latest by sourcetype
```

```spl
index=botsv3 earliest=0 | fieldsummary
```

The export stage will run in bounded time windows and per sourcetype, preserving `_time`, `_indextime`, `index`, `host`, `source`, `sourcetype`, `_raw`, and discovered fields.

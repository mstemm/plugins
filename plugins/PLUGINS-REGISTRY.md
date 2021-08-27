# Introduction

This page documents the known set of Falco source plugins and their associated event IDs. If you wish to author a new plugin, you should create a PR that modifies this file to let the Falcosecurity organization of the new source plugin and to allocate a unique event id for events from the source plugin.

## Known Plugins

### Source Plugins

| Name | Description | Contact | Event ID | Event Source
| ---- | --- | --- | --- | --- | ---
| Cloudtrail | Reads Cloudtrail JSON logs from files/S3 and injects as events | https://github.com/falcosecurity/plugins | 2 | `cloudtrail`
| Dummy | Reference plugin used to document interface | https://github.com/falcosecurity/plugins | 3 | `dummy`
| Dummy C | Like Dummy, but written in C | https://github.com/falcosecurity/plugins | 4 | `dummy`


### Extractor Plugins

If the value for Extract Event Sources, is "N/A", it means that the plugin does not define a set of extract event sources, and as a result will attempt to extract fields from any event.

| Name | Description | Contact | Extract Event Sources
| ---- | --- | --- | --- | --- | ---
| Json | Extracts values from any JSON payload | https://github.com/falcosecurity/plugins | N/A



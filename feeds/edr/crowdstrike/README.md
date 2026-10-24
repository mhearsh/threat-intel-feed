# CrowdStrike Falcon: API helper

`iocs-api.csv` is **not** a native Falcon CSV import format (none is documented). Its columns map 1:1 to the IOC API fields of `POST /iocs/entities/indicators/v1` (type, value, action, platforms, severity, description, source, expiration, applied_globally). Load it with FalconPy or PSFalcon.

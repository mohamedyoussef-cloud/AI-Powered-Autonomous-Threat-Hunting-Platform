# Backend support scripts

Schema creation, data-preparation import and integration verification scripts for the web application.

## Contents
- [`init_db.py`](init_db.py) — implementation of init db
- [`load_pipeline_data.py`](load_pipeline_data.py) — implementation of load pipeline data
- **Additional tracked files:** 2 (see directory listing for complete inventory).

## Interpretation and usage

`init_db.py` creates tables only. Import jobs require authorized source data and correct paths; never assume a public Git clone includes a live database.

[Related overview](../README.md)

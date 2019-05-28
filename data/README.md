data
====
This is the default directory for the data used by the server, including the
database.

The database is an SQLite 3 database file, by default named `storage.sqlite`
in this directory.  The first time the server is run, it will create the
database and the required tables and indexes.

The default configuration file is `config.json` in this directory. You must
create a configuration file before running the server. You can start with
`config-sample.json` or one of the samples in the [../examples](../examples/)
directory, and modify it for your deployment.

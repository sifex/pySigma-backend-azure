> [!CAUTION]
> This backend is no longer maintained. For Defender-coompatible KQL, you should use [AttackIQ's Microsoft 365 Defender backend](https://github.com/AttackIQ/pySigma-backend-microsoft365defender) instead.

# pySigma Azure Backend

This is the Azure backend for pySigma. It provides the package `sigma.backends.azure` with the `AzureBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.azure`:

It supports the following output formats:

* default: plain Azure sentinal / ALA queries

This backend is currently maintained by:

* [Alex](https://github.com/sifex/)

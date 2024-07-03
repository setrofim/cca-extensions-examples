This repo contains example of extending the functionaly of [ccatoken](https://github.com/veraison/ccatoken).

### cert

This is a small example of adding method that accepts x509 certs rather than bare keys for validation.

### claims11

This an example of extending `ccatoken` with additional claims. Specifically the new claims in RMM 1.1 (in darft at the time of writing). This example shows minimal amout of code needed to support handling of new claims for situations where additional extensibility or handling of other profiles is not an issue.

### profile11

This is a more complete implementation of the above, fully defining a new profile, that may be handled along side other PSA profiles using code that works with the generic `psatoken.IClaims`, and may have further profiles defined on top of it.

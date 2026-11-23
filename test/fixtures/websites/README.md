# Website rules

`rules.json` holds the cases the website rules are held to: Bitwarden's
documented examples, shared hosts, IP addresses, ports, and the scenarios of
the `add-cards-identities-and-websites` plan's behaviour. The app's
`test/core/website_rules_test.dart` runs every case through `fillsOn` and
`phoneDomains`, and the browser extension's Dart core runs the same file (the
`add-browser-extension` plan, task 7.6).

It was written by hand, once, for task 6.1, and is **never regenerated**: a
case that turns out wrong is fixed in the code, or, where the file itself is
wrong, by the owner and the server session who settle the rules. It is
unverified until the single build-and-test pass after the plan merged.

Each case has the rule (`match`, Bitwarden's `UriMatchStrategy` number, null
for Default), the saved `uri`, the `address` the browser shows, whether the
rule `fills` there, and the `phones` domains for a login and for an account
holding only that website. `registrable` lists what the Public Suffix List says
for the hosts whose registrable domain isn't themselves.

The kemlock-server session may publish vectors of its own for the web vault;
where the two disagree the server session and the owner settle it.

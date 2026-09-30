# Security policy

openwrt-mcp runs as root on a router and exposes its configuration to an AI agent, so security
reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
*Security* tab -> *Report a vulnerability* on this repository. Include the OpenWrt release,
the openwrt-mcp version (`openwrt-mcp version`), and steps to reproduce.

You should get an answer within a week. Fixes are released as a new version with a
CHANGELOG entry that credits the reporter unless you prefer otherwise.

## Scope

In scope: anything that lets an MCP client act outside the policies granted to it -- scope or
tool bypasses, command or option injection through tool arguments, secrets reaching the audit
log, a rollback that does not restore, the stdio bridge accepting a client it should not.

Out of scope: an agent using exactly the permissions you granted (a broad `exec` or `ubus_call`
grant *is* a root shell, as documented), and access by someone who already has a root login on
the router.

## Supported versions

Only the latest release is supported.

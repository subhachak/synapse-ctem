# spring-cloud-fn-app — CTEM live-remediation target (Spring Cloud Function)

Intentionally-vulnerable Spring Boot app for the Mphasis Synapse CTEM
live-remediation loop. **Do not deploy.**

Carries **CVE-2022-22963** — Spring Cloud Function SpEL RCE. In
`spring-cloud-function` `<= 3.2.2`, the `spring.cloud.function.routing-expression`
HTTP header is evaluated as a SpEL expression, so a single unauthenticated
`POST /functionRouter` runs arbitrary code. The fix is a one-property `pom.xml`
bump (`spring-cloud-function.version` `3.2.2 -> 3.2.3`).

The demo host has no local JDK/Maven, so build, `mvn test`, and the real SpEL
exploit probe run on GitHub Actions (`.github/workflows/ctem-verify.yml`,
`scripts/spel_probe.py`). The CTEM backend pushes a fix branch, dispatches the
workflow, and reads the `CTEM_*` marker lines from the run log to certify
closure.

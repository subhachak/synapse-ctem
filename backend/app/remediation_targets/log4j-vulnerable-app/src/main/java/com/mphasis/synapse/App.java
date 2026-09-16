package com.mphasis.synapse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Minimal diagnostic logger, deliberately modeled on the real-world pattern
 * that made Log4Shell (CVE-2021-44228) so widespread: untrusted,
 * attacker-controlled input (a request header, a username, a search query)
 * reaches a log statement. log4j-core's PatternLayout renders the final
 * message and, on vulnerable versions, evaluates any ${...} lookup syntax
 * found in it -- including a JNDI lookup that triggers an outbound
 * connection to a host an attacker controls.
 *
 * Parameterized logging ({} placeholders, used below) does NOT avoid this --
 * lookup substitution happens at layout-rendering time, on the already-
 * substituted message, not on the literal format string. That's real
 * Log4Shell behavior, not simplified for this demo.
 *
 * There's no HTTP server here on purpose, matching the CTEM demo's other
 * live scenario (node-payments-api): the vulnerable entry point is invoked
 * directly, keeping the runtime probe fast and dependency-free.
 */
public final class App {
    private static final Logger LOGGER = LogManager.getLogger(App.class);

    private App() {
    }

    /** Mirrors a real request-logging call site: untrusted input, logged as-is. */
    public static void logClientMessage(String untrustedInput) {
        LOGGER.info("client message: {}", untrustedInput);
    }

    public static void main(String[] args) {
        String message = args.length > 0 ? args[0] : "no message supplied";
        logClientMessage(message);
    }
}

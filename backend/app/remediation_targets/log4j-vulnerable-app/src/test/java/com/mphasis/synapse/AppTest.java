package com.mphasis.synapse;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Real contract test (this is what CTEM's live remediation runs as
 * `mvn test`, same role `npm test` plays for the node-payments-api target):
 * confirms the app's logging entry point still works after the dependency
 * bump. It intentionally does NOT assert anything about log4j's internal
 * JNDI-lookup behavior -- that's what the runtime probe (scripts/jndi_probe.py)
 * checks, against the real behavior difference between the vulnerable and
 * fixed versions, not a unit-test mock.
 */
class AppTest {

    @Test
    void logsAnOrdinaryMessageWithoutThrowing() {
        assertDoesNotThrow(() -> App.logClientMessage("hello from a contract test"));
    }

    @Test
    void logsAnEmptyMessageWithoutThrowing() {
        assertDoesNotThrow(() -> App.logClientMessage(""));
    }
}

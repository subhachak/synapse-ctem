package com.mphasis.synapse;

import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Real contract test — this is what CTEM's live remediation runs as
 * {@code mvn test}, the same role {@code npm test} plays for the npm targets.
 * Booting the full application context with {@code webEnvironment = NONE} proves
 * the Spring Cloud Function dependency still assembles a valid context and the
 * function bean still resolves after the version bump. It deliberately asserts
 * nothing about the SpEL routing behaviour itself — that is what the runtime
 * exploit probe (scripts/spel_probe.py) checks, against the real behaviour
 * difference between the vulnerable and fixed versions.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class ApplicationTest {

    @Autowired
    private Function<String, String> uppercase;

    @Test
    void contextLoadsAndFunctionResolves() {
        assertNotNull(uppercase, "the uppercase function bean should be wired");
    }

    @Test
    void functionStillBehaves() {
        assertEquals("HELLO", uppercase.apply("hello"));
    }
}

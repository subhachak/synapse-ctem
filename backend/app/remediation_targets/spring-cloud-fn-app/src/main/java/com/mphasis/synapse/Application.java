package com.mphasis.synapse;

import java.util.function.Function;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * Minimal Spring Boot service exposing a Spring Cloud Function. The single
 * {@code uppercase} function bean gives spring-cloud-function-web a catalog to
 * serve, which auto-registers the POST /functionRouter endpoint.
 *
 * On the vulnerable dependency version (<= 3.2.2), /functionRouter evaluates
 * the {@code spring.cloud.function.routing-expression} request header as a SpEL
 * expression before routing — so a single unauthenticated request runs
 * arbitrary code (CVE-2022-22963). Nothing in this class is itself unsafe; the
 * vulnerability lives entirely in the dependency, which is exactly why the fix
 * is a version bump and not a code change.
 */
@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public Function<String, String> uppercase() {
        return value -> value == null ? "" : value.toUpperCase();
    }
}

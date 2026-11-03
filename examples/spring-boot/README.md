# Spring Boot + Keystone Vault

A minimal Spring Boot 4 service (`orders-service`) that loads its whole configuration, secrets
included, from Keystone Vault before the application context starts. It was verified against a
running Keystone (`back/tests/spring_e2e.rs`).

## 1. In Keystone (admin console)

1. **New application**: id `orders-service` (its Portal `client_id`), with your environments,
   for example `qa, uat, prod`. Each application defines its own environments, and more can be
   added at any time.
2. Pick the **qa** environment:
   - **Files → Upload** your `application.properties` for qa. It is stored whole and merged into
     what the app receives.
   - **Keys → Add key** for secrets you want rotated and audited one by one, for example
     `spring.datasource.password`. A key overrides the same property from a file.
   - Values shared by every environment go in **default**.
3. **Access tokens → Issue token** for environment `qa`. Copy it once.

## 2. In the app

`pom.xml` adds one dependency, `spring-cloud-starter-config`. `application.properties`, the only
configuration committed to source control, contains:

```properties
spring.application.name=orders-service
spring.config.import=configserver:
spring.cloud.config.uri=${KEYSTONE_URL}/config
spring.cloud.config.username=keystone
spring.cloud.config.password=${KEYSTONE_TOKEN}
spring.cloud.config.fail-fast=true
```

## 3. Run

```sh
mvn package
KEYSTONE_URL=https://keystone.example.com KEYSTONE_TOKEN=ksv_… java -jar target/orders-service-0.0.1.jar
```

`KEYSTONE_TOKEN` comes from the deployment's secret store: a Kubernetes Secret, a systemd
`LoadCredential=`, or your CI/CD secret variables. It is the only secret the app holds, and it can
only read its own environment.

## What the app receives

The token decides the environment. For a qa token, highest precedence first:

1. qa keys (for example `spring.datasource.password`)
2. qa `.properties` files (for example `application.properties`)
3. default keys
4. default `.properties` files

Spring sees these as ordinary property sources, so `@Value`, `@ConfigurationProperties` and
`spring.datasource.*` work unchanged. With `fail-fast=true`, a wrong, revoked or expired token, or
an unreachable Keystone, stops startup instead of letting the app run on defaults.

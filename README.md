# spring-oauth2-resourceserver

Demo spring application that illustrates oauth2 Resource server configuration

# Basic config

just add to _application.properties_

```properties
spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://auth-server/jwk
spring.security.oauth2.resourceserver.jwt.jws-algorithm=PS512
```

or

```properties
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://auth-server/.well-known/oauth-authorization-server
```

# Roles

If your application supports roles, then check

Enable annotation based role security: ```@EnableGlobalMethodSecurity(jsr250Enabled = true)```

Enable role security for endpoint: ```@RolesAllowed("demo-admin")```

Role parsing: ```com.github.bademux.spring_oauth2_resourceserver.Application.Config.jwtAuthenticationConverter```

# Testing

Check ```com.github.bademux.spring_oauth2_resourceserver.AuthTestSpec``` for integration tests

# Run locally with Security disabled

pass arguments --security.enabled=false --spring.main.lazy-initialization=true

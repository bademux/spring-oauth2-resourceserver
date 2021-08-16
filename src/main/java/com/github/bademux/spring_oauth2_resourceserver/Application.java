package com.github.bademux.spring_oauth2_resourceserver;


import lombok.RequiredArgsConstructor;
import lombok.experimental.Delegate;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toList;

@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
@RequiredArgsConstructor
public class Application implements AutoCloseable {

    public static final String API_PREFIX = "/api";

    @Delegate(types = AutoCloseable.class)
    private final ConfigurableApplicationContext context;

    public static void main(String... args) {
        run(args);
    }

    public static Application run(String... args) {
        return new SpringApplicationBuilder(Application.class, Config.class, WebSecurityConfigurer.class)
                .main(Application.class)
                .build()
                .run(args)
                .getBean(Application.class);
    }

    public int getPort() {
        return requireNonNull(context.getEnvironment().getProperty("local.server.port", int.class));
    }

    public int getAdminPort() {
        return requireNonNull(context.getEnvironment().getProperty("local.management.server.port", int.class, getPort()));
    }

    @ConditionalOnProperty(value = "security.enabled", havingValue = "true", matchIfMissing = true)
    @EnableWebSecurity
    @EnableGlobalMethodSecurity(jsr250Enabled = true)
    public static class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                    .authorizeRequests().mvcMatchers(API_PREFIX).authenticated();
        }

    }

    @Configuration
    public static class Config {

        /**
         * Grabs roles from 'JWT.realm_access.roles' and prefixes it with default spring role prefix 'ROLE_'
         */
        @Bean
        @SuppressWarnings("unchecked")
        JwtAuthenticationConverter jwtAuthenticationConverter() {
            var converter = new JwtAuthenticationConverter();
            converter.setJwtGrantedAuthoritiesConverter(jwt -> Optional.of(jwt.getClaims())
                    .map(map -> (Map<String, ?>) map.get("realm_access"))
                    .map(map -> (Collection<String>) map.get("roles"))
                    .stream()
                    .flatMap(Collection::stream)
                    .map(roleName -> "ROLE_" + roleName)
                    .map(SimpleGrantedAuthority::new)
                    .collect(toList()));
            return converter;
        }

    }

}

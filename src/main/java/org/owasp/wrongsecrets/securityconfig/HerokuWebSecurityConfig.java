package org.owasp.wrongsecrets.securityconfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/** Used to implement https redirect for our Heroku-hosted workload. */
@Configuration
public class HerokuWebSecurityConfig {

  @Bean
  @Order(1)
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http.redirectToHttps(
            redirect ->
                redirect.httpsRedirectWhen(
                    r ->
                       r.getRequest().getURI().toString().contains("heroku")
                            && (r.getRequest().getHeaders().containsKey("X-Forwarded-Proto")
                                || r.getRequest().getHeaders().containsKey("x-forwarded-proto"))));
        return http.build();
  }
}

package com.example.opasecdemo;

import com.example.opasecdemo.model.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.function.Supplier;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Autowired
    ObjectMapper mapper;
    public AuthorizationManager<RequestAuthorizationContext> authorizationManager() {
        return (auth, context) -> {
            HttpResponse<String> response = callOPA(auth, context);
            return decideDecision(response);
        };
    }

    /**
     * https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html
     *
     * @param http
     * @return
     * @throws AuthenticationException
     */
    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().access(authorizationManager()))
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }

    Body buildBody(RequestAuthorizationContext context) {
        Body body = new Body();
        Input input = new Input();
        body.setInput(input);

        Attribute attributes = new Attribute();
        input.setAttributes(attributes);

        Request request = new Request();
        attributes.setRequest(request);

        HttpServletRequest httpRequest = context.getRequest();
        String token = httpRequest.getHeader("authorization");

        Http http = new Http(httpRequest.getMethod(), httpRequest.getRequestURI(), new Header(token));
        request.setHttp(http);

        System.out.println(httpRequest.getMethod() + ", " + httpRequest.getRequestURI() + ", " + token);
        return body;
    }

    AuthorizationDecision decideDecision(HttpResponse<String> Response) {
        if (Response.statusCode() != 200) {
            return new AuthorizationDecision(false);
        }

        try {
            Response response = mapper.readValue(Response.body(), Response.class);
            return new AuthorizationDecision(response.getResult().isAllow());
        } catch (JsonProcessingException je) {
            throw new RuntimeException(je);
        }
    }

    HttpResponse<String> callOPA(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
        var client = HttpClient.newBuilder().build();

        try {
            var request = HttpRequest.newBuilder()
                    .uri(new URI("http://localhost:8181/v1/data/envoy/authz"))
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(buildBody(context))))
                    .build();

            return client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
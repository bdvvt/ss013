package org.example.apigateway.routes;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

@Component
public class RouterValidator {

    AntPathMatcher antPathMatcher = new AntPathMatcher();

    // định nghĩa route open (không cần phải xác thực)
    public static final List<String> openAPIEndpoints = List.of(
            "/api/v1/auth/register",
            "/api/v1/auth/login"
    );

    // định nghĩa route private (cần phải xác thực kèm theo role)
    public static final Map<String,List<String>> rolePrivate = Map.of(
            "/api/v1/categories/**",List.of("ROLE_ADMIN")
    );

    public Predicate<ServerHttpRequest> isSecured = req -> {
        String path = req.getURI().getPath();
        return openAPIEndpoints.stream().noneMatch(uri -> antPathMatcher.match(uri, path));
    };

    public List<String> getRequiredRoles(String path) {
        return rolePrivate.entrySet().stream()
                .filter(entry -> antPathMatcher.match(entry.getKey(),path))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(Collections.emptyList());
    }

}
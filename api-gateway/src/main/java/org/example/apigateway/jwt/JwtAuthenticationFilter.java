package org.example.apigateway.jwt;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.apache.http.HttpHeaders;
import org.example.apigateway.routes.RouterValidator;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {
    private final RouterValidator routerValidator;
    private final JwtUtils jwtUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (routerValidator.isSecured.test(request)) {

            // Tiếp theo kiểm tra xem request có gửi token lên không
            // Authorization: Bearer álkdjaskldjlasjdlas
            if (!request.getHeaders().containsHeader("AUTHORIZATION")) {
                // Không tồn tại xử lý lỗi là 401 mang theo token theo
                return onError(exchange, HttpStatus.UNAUTHORIZED); // lỗi 401 ko mang theo token
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                try {

                    if (!jwtUtils.validationToken(token)) {
                        return onError(exchange, HttpStatus.UNAUTHORIZED);
                    }

                    // Giải mã token lấy thông tin trong payload
                    Claims claims = jwtUtils.extractAllClaims(token);

                    // Lấy path đường dẫn ừ request để kiểm tra
                    String path = request.getURI().getPath();

                    List<String> requiredRoles = routerValidator.getRequiredRoles(path);

                    if (!requiredRoles.isEmpty()) {
                        ObjectMapper objectMapper = new ObjectMapper();
                        // cần lấy role có trong token
                        String userRoleRaw = claims.get("roles", String.class); // JSON: {"id":1,"roleName":"ROLE_ADMIN"}
                        JsonNode rolesNode = objectMapper.readTree(userRoleRaw);
                        List<String> userRoles = new ArrayList<>();

                        for (JsonNode roleNode : rolesNode) {
                            userRoles.add(roleNode.get("roleName").asText());
                        }

                        // Cắt nó và chuyển đổi thành Collections (ArrayList)
//                        List<String> userRoles = objectMapper.readValue(
//                                userRoleRaw,
//                                new TypeReference<List<String>>() {}
//                        );

                        boolean hasPermisson = userRoles.stream().anyMatch(requiredRoles::contains);

                        if (!hasPermisson) {
                            return onError(exchange, HttpStatus.FORBIDDEN);
                        }

                        Object userIdObj = claims.get("userId");
                        String userIdStr = userIdObj != null ? String.valueOf(userIdObj) : "";

                        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                                .header("X-Auth-UserId",userIdStr)
                                .header("X-Auth-Roles",claims.get("roles",String.class))
                                .build();

                        return chain.filter(exchange.mutate().request(modifiedRequest).build());
                    }

                } catch (Exception e) {
                    return onError(exchange, HttpStatus.UNAUTHORIZED);
                }
            } else {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }


        }

        return chain.filter(exchange);
    }

    public Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
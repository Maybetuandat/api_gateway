package com.example.gateway.filter;

import com.example.gateway.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);
    private final JwtUtil jwtUtil;

    public AuthenticationFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();
            
            logger.info("=== Processing request: {}", path);

            // Kiểm tra nếu là WebSocket request
            HttpHeaders headers = request.getHeaders();
            boolean isWebSocket = headers.getUpgrade() != null && 
                                 "websocket".equalsIgnoreCase(headers.getFirst(HttpHeaders.UPGRADE));

            String authHeader = null;

            if (isWebSocket) {
                // Với WebSocket, lấy token từ query parameter
                logger.info("🔌 WebSocket request detected");
                String tokenParam = request.getQueryParams().getFirst("token");
                
                if (tokenParam != null && !tokenParam.isEmpty()) {
                    authHeader = "Bearer " + tokenParam;
                    logger.info("Token extracted from query parameter");
                } else {
                    logger.error("Missing token in query parameter for WebSocket path: {}", path);
                    return onError(exchange, "Missing token in query parameter", HttpStatus.UNAUTHORIZED);
                }
            } else {
                // Với HTTP request thông thường, lấy từ Authorization header
                if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                    logger.error("Missing authorization header for path: {}", path);
                    return onError(exchange, "Missing authorization header", HttpStatus.UNAUTHORIZED);
                }

                authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
                logger.info("Authorization header: {}", authHeader);
            }

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                logger.error("Invalid authorization header format");
                return onError(exchange, "Invalid authorization header", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            logger.info("Extracted token: {}...", token.substring(0, Math.min(20, token.length())));

            try {
                boolean isValid = jwtUtil.validateToken(token);
                logger.info("Token validation result: {}", isValid);
                
                if (!isValid) {
                    logger.error("Token validation failed!");
                    return onError(exchange, "Invalid or expired token", HttpStatus.UNAUTHORIZED);
                }

                String username = jwtUtil.extractUsername(token);
                Integer userId = jwtUtil.extractUserId(token);
                
                logger.info("Token valid - Username: {}, UserId: {}", username, userId);

                ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                        .header("X-User-Id", String.valueOf(userId))
                        .header("X-Username", username)
                        .build();

                return chain.filter(exchange.mutate().request(modifiedRequest).build());

            } catch (Exception e) {
                logger.error("Token validation exception: ", e);
                return onError(exchange, "Token validation failed: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
            }
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        logger.error("Sending error response: {} - {}", status, message);
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        String errorResponse = String.format("{\"error\":\"%s\"}", message);
        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(errorResponse.getBytes()))
        );
    }

    public static class Config {
    }
}
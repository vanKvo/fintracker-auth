package com.fintracker.auth.config;

import com.fintracker.auth.filter.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * Security configuration for Spring Security integration.
 * Configures JWT authentication filter, CORS, CSRF protection, and session management.
 * 
 * This configuration:
 * - Integrates the JwtAuthenticationFilter for token validation
 * - Enables CORS for cross-origin API requests
 * - Disables CSRF for stateless API (tokens are in headers)
 * - Sets session creation policy to STATELESS (JWT-based)
 * - Permits public endpoints (auth endpoints)
 * - Requires authentication for protected endpoints
 * 
 * @author fintracker-auth
 * @version 1.0.0
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Constructs a SecurityConfig with the provided JWT filter.
     *
     * @param jwtAuthenticationFilter the JWT authentication filter
     */
    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    /**
     * Configures the security filter chain for HTTP requests.
     * 
     * Configuration:
     * - CORS enabled for cross-origin requests
     * - CSRF disabled (stateless API with token authentication)
     * - Session creation set to STATELESS (no server-side sessions)
     * - Public endpoints: /auth/register, /auth/login, /auth/refresh, /auth/verify, /auth/forgot-password, /auth/reset-password, /auth/check-email
     * - JWT filter added before standard authentication filter
     * - All other requests require authentication
     * 
     * @param http the HttpSecurity object to configure
     * @return the configured SecurityFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        // Public endpoints - no authentication required
                        .requestMatchers("/auth/register").permitAll()
                        .requestMatchers("/auth/login").permitAll()
                        .requestMatchers("/auth/refresh").permitAll()
                        .requestMatchers("/auth/verify").permitAll()
                        .requestMatchers("/auth/forgot-password").permitAll()
                        .requestMatchers("/auth/reset-password").permitAll()
                        .requestMatchers("/auth/confirm-user-email").permitAll()
                        .requestMatchers("/auth/resend-confirmation-code").permitAll()
                        .requestMatchers("/auth/check-email").permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/auth/info").permitAll()
                        // All other requests require authentication
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Configures CORS (Cross-Origin Resource Sharing) settings.
     * 
     * CORS is important for allowing browser-based clients to make requests
     * to this API from different origins (different domains, ports, protocols).
     * 
     * Current configuration:
     * - Allowed origins: All origins (*)
     * - Allowed methods: GET, POST, PUT, DELETE, OPTIONS
     * - Allowed headers: All headers (Content-Type, Authorization, etc.)
     * - Allow credentials: Enabled for cookies and authorization headers
     * - Max age: 3600 seconds (1 hour) - how long CORS preflight results are cached
     * 
     * For production, restrict origins to specific domains:
     * allowedOrigins = Arrays.asList("https://yourdomain.com", "https://app.yourdomain.com")
     * 
     * @return CorsConfigurationSource configured for the API
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Allowed origins
        configuration.setAllowedOrigins(Arrays.asList("*"));
        
        // Allowed HTTP methods
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        
        // Allowed headers
        configuration.setAllowedHeaders(Arrays.asList("*"));
        
        // Allow credentials (cookies, authorization headers)
        configuration.setAllowCredentials(true);
        
        // Max age for preflight cache (in seconds)
        configuration.setMaxAge(3600L);
        
        // Exposed headers (headers that browsers are allowed to access)
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Total-Count" // Useful for pagination
        ));
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}

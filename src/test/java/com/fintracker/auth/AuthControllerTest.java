package com.fintracker.auth;


import com.fintracker.auth.controller.AuthController;
import com.fintracker.auth.dto.*;
import com.fintracker.auth.service.IAuthService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class AuthControllerTest {

    //private static StreamLambdaHandler handler;
    //private static Context lambdaContext;
    private static IAuthService authService;
    private static AuthController authController;

    @BeforeAll
    public static void setUp() {
        /* Prevent Spring Boot from starting an embedded web server during tests
        System.setProperty("spring.main.web-application-type", "none");
        System.setProperty("server.port", "0");*/
        authService = mock(IAuthService.class);
        authController = new AuthController(authService);

        //handler = new StreamLambdaHandler();
        //lambdaContext = new MockLambdaContext();
    }

    /*@AfterAll
    public static void tearDown() {
        // Clean up properties so other tests are not affected
        System.clearProperty("spring.main.web-application-type");
        System.clearProperty("server.port");
    }*/

    @Test
    void getInfo_returnsRunningMessage() {
        var resp = authController.getInfo();
        assertEquals(200, resp.getStatusCode().value());
        assertEquals("Auth Service is running.", resp.getBody());
    }

    @Test
    void register_delegatesToService_andReturnsCreated() {
        var req = UserRegistrationRequest.builder()
                .email("test@example.com")
                .password("P4ssword!")
                .fullName("Test User")
                .build();

        var expected = UserProfileResponse.builder()
                .userId("id-123")
                .email(req.getEmail())
                .fullName(req.getFullName())
                .role("user")
                .emailVerified(false)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        when(authService.registerUser(req)).thenReturn(expected);

        var resp = authController.register(req);

        assertEquals(201, resp.getStatusCode().value());
        assertSame(expected, resp.getBody());
        verify(authService, times(1)).registerUser(req);
    }

    @Test
    void login_returnsAuthTokenResponse() {
        var req = UserLoginRequest.builder().email("a@b.com").password("pw").build();
        var expected = AuthTokenResponse.builder().accessToken("t").refreshToken("r").idToken("i").tokenType("Bearer").expiresIn(3600).build();
        when(authService.login(req)).thenReturn(expected);

        var resp = authController.login(req);

        assertEquals(200, resp.getStatusCode().value());
        assertSame(expected, resp.getBody());
        verify(authService, times(1)).login(req);
    }

    @Test
    void refreshToken_delegatesAndReturnsTokens() {
        var req = new RefreshTokenRequest();
        req.setRefreshToken("refresh");
        var expected = AuthTokenResponse.builder().accessToken("new").build();
        when(authService.refreshToken(req)).thenReturn(expected);

        var resp = authController.refreshToken(req);

        assertEquals(200, resp.getStatusCode().value());
        assertSame(expected, resp.getBody());
        verify(authService).refreshToken(req);
    }

    @Test
    void verifyToken_returnsVerificationResponse() {
        var token = "token123";
        var expected = TokenVerificationResponse.builder().valid(true).userId("u1").email("e@x").build();
        when(authService.verifyAccessToken(token)).thenReturn(expected);

        var resp = authController.verifyToken(token);

        assertEquals(200, resp.getStatusCode().value());
        assertSame(expected, resp.getBody());
        verify(authService).verifyAccessToken(token);
    }

    @Test
    void getProfile_extractsBearerAndReturnsProfile() {
        var token = "tok";
        var header = "Bearer " + token;
        var expected = UserProfileResponse.builder().userId("u").email("e").build();
        when(authService.getUserProfile(token)).thenReturn(expected);

        var resp = authController.getProfile(header);

        assertEquals(200, resp.getStatusCode().value());
        assertSame(expected, resp.getBody());
        verify(authService).getUserProfile(token);
    }

    @Test
    void getProfile_withInvalidHeader_throws() {
        assertThrows(IllegalArgumentException.class, () -> authController.getProfile("Invalid header"));
    }

    @Test
    void changePassword_callsService_andReturnsNoContent() {
        var token = "tk";
        var header = "Bearer " + token;
        var req = UserChangePasswordRequest.builder().currentPassword("old").newPassword("new").build();

        var resp = authController.changePassword(header, req);

        assertEquals(204, resp.getStatusCode().value());
        verify(authService).changePassword(token, req);
    }

    @Test
    void logout_callsService_andReturnsMessage() {
        var req = UserLogoutRequest.builder().accessToken("a").build();
        var resp = authController.logout(req);

        assertEquals(200, resp.getStatusCode().value());
        assertEquals(Map.of("message", "Logout successful"), resp.getBody());
        verify(authService).logout(req);
    }

    @Test
    void initiatePasswordReset_andConfirmPasswordReset_andResendConfirmation() {
        var email = "x@y.com";
        var map = Map.of("email", email);
        var resp1 = authController.initiatePasswordReset(map);
        assertEquals(200, resp1.getStatusCode().value());
        assertEquals(Map.of("message", "Password reset email sent"), resp1.getBody());
        verify(authService).initiatePasswordReset(email);

        var resetMap = Map.of("email", email, "confirmationCode", "1234", "newPassword", "N1");
        var resp2 = authController.confirmPasswordReset(resetMap);
        assertEquals(200, resp2.getStatusCode().value());
        assertEquals(Map.of("message", "Password reset successful"), resp2.getBody());
        verify(authService).confirmPasswordReset(email, "1234", "N1");

        var resp3 = authController.resendConfirmationCode(map);
        assertEquals(200, resp3.getStatusCode().value());
        assertEquals(Map.of("message", "Confirmation code resent successfully"), resp3.getBody());
        verify(authService).resendConfirmationCode(email);
    }

    @Test
    void checkEmail_returnsRegisteredFlag() {
        when(authService.isEmailRegistered("a@b.com")).thenReturn(true);
        var resp = authController.checkEmail("a@b.com");
        assertEquals(200, resp.getStatusCode().value());
        assertEquals(Map.of("registered", true), resp.getBody());
        verify(authService).isEmailRegistered("a@b.com");
    }

    @Test
    void confirmUserEmail_callsService_andReturnsMessage() {
        var body = Map.of("email", "e@x", "confirmationCode", "c1");
        var resp = authController.confirmUserEmail(body);
        assertEquals(200, resp.getStatusCode().value());
        assertEquals(Map.of("message", "Confirmation of user email successful"), resp.getBody());
        verify(authService).confirmUserEmail("e@x", "c1");
    }

   /* @Test
    public void ping_streamRequest_respondsWithHello() {
        InputStream requestStream = new AwsProxyRequestBuilder("/ping", HttpMethod.GET)
                                            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                                            .buildStream();
        ByteArrayOutputStream responseStream = new ByteArrayOutputStream();

        handle(requestStream, responseStream);

        AwsProxyResponse response = readResponse(responseStream);
        assertNotNull(response);
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatusCode());

        assertFalse(response.isBase64Encoded());

        assertTrue(response.getBody().contains("pong"));
        assertTrue(response.getBody().contains("Hello, World!"));

        assertTrue(response.getMultiValueHeaders().containsKey(HttpHeaders.CONTENT_TYPE));
        assertTrue(response.getMultiValueHeaders().getFirst(HttpHeaders.CONTENT_TYPE).startsWith(MediaType.APPLICATION_JSON));
    }

    @Test
    public void invalidResource_streamRequest_responds404() {
        InputStream requestStream = new AwsProxyRequestBuilder("/pong", HttpMethod.GET)
                                            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                                            .buildStream();
        ByteArrayOutputStream responseStream = new ByteArrayOutputStream();

        handle(requestStream, responseStream);

        AwsProxyResponse response = readResponse(responseStream);
        assertNotNull(response);
        assertEquals(Response.Status.NOT_FOUND.getStatusCode(), response.getStatusCode());
    }

    private void handle(InputStream is, ByteArrayOutputStream os) {
        try {
            handler.handleRequest(is, os, lambdaContext);
        } catch (IOException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    private AwsProxyResponse readResponse(ByteArrayOutputStream responseStream) {
        try {
            return LambdaContainerHandler.getObjectMapper().readValue(responseStream.toByteArray(), AwsProxyResponse.class);
        } catch (IOException e) {
            e.printStackTrace();
            fail("Error while parsing response: " + e.getMessage());
        }
        return null;
    }*/
}

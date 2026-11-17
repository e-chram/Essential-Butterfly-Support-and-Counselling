
package ca.sheridancollege.shtirthb.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.LocalDateTime;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.test.util.ReflectionTestUtils;

import ca.sheridancollege.shtirthb.model.AdminUser;
import ca.sheridancollege.shtirthb.model.ClientUser;
import ca.sheridancollege.shtirthb.model.PasswordResetToken;
import ca.sheridancollege.shtirthb.repository.AdminUserRepository;
import ca.sheridancollege.shtirthb.repository.ClientUserRepository;
import ca.sheridancollege.shtirthb.repository.PasswordResetTokenRepository;
import jakarta.mail.BodyPart;
import jakarta.mail.Multipart;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;

/*
 * Integration tests for the forgotten password journey:
 *   user asks for a reset -> a one-time token is created -> user sets a new
 *   password with the token -> the old password stops working.
 *
 * Real application, real PostgreSQL (Testcontainers), real security rules.
 * The reset token is extracted from the mocked outgoing email. The database
 * stores only its SHA-256 hash.
 * Every test is rolled back at the end.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:tc:postgresql:17:///password_reset_flow_test",
        "spring.datasource.driver-class-name=org.testcontainers.jdbc.ContainerDatabaseDriver",
        "spring.datasource.username=test",
        "spring.datasource.password=test",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.jpa.show-sql=false",
        "app.jwt.secret=integration-test-secret-integration-test-secret-1234567890",
        "app.admin.email=admin@test.com",
        "app.admin.password=Admin@12345",
        "app.mail.from-address=noreply@butterfly.test"
})
@AutoConfigureMockMvc
@Transactional
class PasswordResetFlowIntegrationTest {

    private static final String EMAIL = "jane@mail.com";
    private static final String OLD_PASSWORD = "OldPassword1";
    private static final String NEW_PASSWORD = "NewPassword1";
    private static final String GENERIC_ANSWER =
            "If an account exists with this email, a password reset link has been generated.";

    @Autowired MockMvc mvc;
    @Autowired ClientUserRepository clients;
    @Autowired AdminUserRepository admins;
    @Autowired PasswordResetTokenRepository tokens;
    @Autowired PasswordEncoder encoder;

    // Email delivery is mocked so the test can inspect the outgoing message.
    @MockitoBean JavaMailSender mailSender;

    @BeforeEach
    void setUp() {
        when(mailSender.createMimeMessage())
                .thenAnswer(call -> new MimeMessage((Session) null));

        clients.save(new ClientUser(
                "Jane Lee",
                EMAIL,
                encoder.encode(OLD_PASSWORD)
        ));
    }

    // ---------------------------------------------------------------- helpers

    private ResultActions forgot(String email) throws Exception {
        return mvc.perform(post("/api/password/forgot").param("email", email));
    }

    private ResultActions reset(
            String token,
            String password,
            String confirm) throws Exception {

        return mvc.perform(post("/api/password/reset")
                .contentType(MediaType.APPLICATION_JSON)
                .content(String.format(
                        "{\"token\":\"%s\",\"newPassword\":\"%s\",\"confirmPassword\":\"%s\"}",
                        token, password, confirm)));
    }

    private ResultActions login(String email, String password) throws Exception {
        return mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(String.format(
                        "{\"email\":\"%s\",\"password\":\"%s\"}",
                        email, password)));
    }

    private PasswordResetToken onlyToken() {
        List<PasswordResetToken> all = tokens.findAll();
        assertEquals(1, all.size());
        return all.get(0);
    }

    private String requestedClientToken() throws Exception {
        return requestedToken(EMAIL);
    }

    /**
     * Requests a password reset, captures the outgoing email and extracts
     * the raw token from its reset-password link.
     */
    private String requestedToken(String email) throws Exception {
        forgot(email)
                .andExpect(status().isOk())
                .andExpect(content().string(GENERIC_ANSWER));

        ArgumentCaptor<MimeMessage> messageCaptor =
                ArgumentCaptor.forClass(MimeMessage.class);

        verify(mailSender).send(messageCaptor.capture());

        MimeMessage sentMessage = messageCaptor.getValue();

        String emailContent = extractText(sentMessage.getContent());

        Matcher matcher = Pattern.compile(
                "/reset-password\\?token=([a-f0-9-]+)"
        ).matcher(emailContent);

        if (!matcher.find()) {
            throw new AssertionError(
                    "Password reset token was not found in the outgoing email."
            );
        }

        return matcher.group(1);
    }

    /**
     * Extracts text recursively from plain-text, HTML and multipart email
     * content. This supports the multipart message created by
     * PasswordResetMailService.
     */
    private String extractText(Object content) throws Exception {

        if (content instanceof String text) {
            return text;
        }

        if (content instanceof Multipart multipart) {
            StringBuilder result = new StringBuilder();

            for (int i = 0; i < multipart.getCount(); i++) {
                BodyPart bodyPart = multipart.getBodyPart(i);
                result.append(extractText(bodyPart.getContent()));
                result.append('\n');
            }

            return result.toString();
        }

        return "";
    }

    private static String hash(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256")
                            .digest(value.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private boolean clientPasswordIs(String password) {
        return encoder.matches(
                password,
                clients.findByEmail(EMAIL).orElseThrow().getPassword()
        );
    }

    // -------------------------------------------------------- asking for a reset

    @Test
    void asking_createsAOneTimeTokenThatLastsThirtyMinutes() throws Exception {
        forgot(EMAIL)
                .andExpect(status().isOk())
                .andExpect(content().string(GENERIC_ANSWER));

        PasswordResetToken token = onlyToken();
        Long clientId = clients.findByEmail(EMAIL).orElseThrow().getId();

        assertEquals("CLIENT", token.getUserType());
        assertEquals(clientId, token.getClientUser().getId());
        assertEquals(64, token.getTokenHash().length());
        assertFalse(token.isUsed());
        assertTrue(token.getExpiresAt().isAfter(LocalDateTime.now().plusMinutes(29)));
        assertTrue(token.getExpiresAt().isBefore(LocalDateTime.now().plusMinutes(31)));
    }

    @Test
    void anUnknownEmail_getsTheSameAnswerAndNoToken() throws Exception {
        // The answer must not reveal whether an account exists.
        forgot("nobody@mail.com")
                .andExpect(status().isOk())
                .andExpect(content().string(GENERIC_ANSWER));

        assertEquals(0, tokens.count());
    }

    @Test
    void anInvalidEmail_isRejected() throws Exception {
        forgot("not-an-email").andExpect(status().isBadRequest());

        assertEquals(0, tokens.count());
    }

    @Test
    void theEmailIsTrimmedAndCaseDoesNotMatter() throws Exception {
        forgot("  JANE@Mail.COM ").andExpect(status().isOk());

        assertEquals(1, tokens.count());
    }

    @Test
    void anAdminEmail_getsAnAdminToken() throws Exception {
        AdminUser admin = admins.findByEmail("admin@test.com").orElseThrow();

        forgot("admin@test.com").andExpect(status().isOk());

        PasswordResetToken token = onlyToken();

        assertEquals("ADMIN", token.getUserType());
        assertEquals(admin.getId(), token.getAdminUser().getId());
    }

    // --------------------------------------------------------- setting the new one

    @Test
    void withTheToken_theClientCanSetANewPasswordAndLogInWithIt() throws Exception {
        String token = requestedClientToken();

        reset(token, NEW_PASSWORD, NEW_PASSWORD)
                .andExpect(status().isOk())
                .andExpect(content().string("Password reset successfully."));

        login(EMAIL, NEW_PASSWORD).andExpect(status().isOk());
    }

    @Test
    void afterTheReset_theOldPasswordNoLongerWorks() throws Exception {
        String token = requestedClientToken();

        reset(token, NEW_PASSWORD, NEW_PASSWORD)
                .andExpect(status().isOk());

        login(EMAIL, OLD_PASSWORD).andExpect(status().isUnauthorized());
    }

    @Test
    void theNewPassword_isStoredHashed() throws Exception {
        String token = requestedClientToken();

        reset(token, NEW_PASSWORD, NEW_PASSWORD)
                .andExpect(status().isOk());

        String stored = clients.findByEmail(EMAIL).orElseThrow().getPassword();

        assertFalse(NEW_PASSWORD.equals(stored));
        assertTrue(encoder.matches(NEW_PASSWORD, stored));
    }

    @Test
    void aToken_canOnlyBeUsedOnce() throws Exception {
        String token = requestedClientToken();

        reset(token, NEW_PASSWORD, NEW_PASSWORD)
                .andExpect(status().isOk());

        assertTrue(onlyToken().isUsed());

        reset(token, "AnotherPass1", "AnotherPass1")
                .andExpect(status().isBadRequest())
                .andExpect(content().string(
                        "Invalid, expired, or already used reset token."
                ));

        assertTrue(clientPasswordIs(NEW_PASSWORD));
    }

    @Test
    void anUnknownToken_isRejected() throws Exception {
        reset("not-a-real-token", NEW_PASSWORD, NEW_PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(content().string(
                        "Invalid, expired, or already used reset token."
                ));

        assertTrue(clientPasswordIs(OLD_PASSWORD));
    }

    @Test
    void anExpiredToken_isRejected() throws Exception {
        ClientUser client = clients.findByEmail(EMAIL).orElseThrow();

        LocalDateTime now = LocalDateTime.now();

        PasswordResetToken expiredToken = PasswordResetToken.forClient(
                hash("expired-token"),
                client,
                now.minusMinutes(1)
        );

        // The expiry must be after creation, even though both are in the past.
        ReflectionTestUtils.setField(
                expiredToken,
                "createdAt",
                now.minusHours(1)
        );

        tokens.saveAndFlush(expiredToken);

        reset("expired-token", NEW_PASSWORD, NEW_PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(content().string(
                        "Invalid, expired, or already used reset token."
                ));

        assertTrue(clientPasswordIs(OLD_PASSWORD));
    }

    @Test
    void passwordsThatDoNotMatch_changeNothingAndKeepTheTokenUsable() throws Exception {
        String token = requestedClientToken();

        reset(token, NEW_PASSWORD, "SomethingElse1")
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Passwords do not match."));

        assertTrue(clientPasswordIs(OLD_PASSWORD));
        assertFalse(onlyToken().isUsed());

        // The user can still finish the reset with the same token.
        reset(token, NEW_PASSWORD, NEW_PASSWORD)
                .andExpect(status().isOk());
    }

    @Test
    void aShortPassword_isRejectedAndKeepsTheTokenUsable() throws Exception {
        String token = requestedClientToken();

        reset(token, "short1", "short1")
                .andExpect(status().isBadRequest());

        assertTrue(clientPasswordIs(OLD_PASSWORD));
        assertFalse(onlyToken().isUsed());
    }

    @Test
    void missingFields_areRejected() throws Exception {
        mvc.perform(post("/api/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // ------------------------------------------------------------------- admins

    @Test
    void anAdminReset_clearsTheLoginLockAndTheNewPasswordWorks() throws Exception {
        AdminUser admin = admins.findByEmail("admin@test.com").orElseThrow();

        admin.setFailedLoginAttempts(5);
        admin.setLockedUntil(LocalDateTime.now().plusMinutes(15));
        admins.save(admin);

        String token = requestedToken("admin@test.com");

        reset(token, NEW_PASSWORD, NEW_PASSWORD)
                .andExpect(status().isOk());

        AdminUser after = admins.findByEmail("admin@test.com").orElseThrow();

        assertEquals(0, after.getFailedLoginAttempts());
        assertNull(after.getLockedUntil());

        // The admin login is a two-step login: the password is accepted
        // and an email code is requested.
        login("admin@test.com", NEW_PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requiresOtp").value(true));
    }
}

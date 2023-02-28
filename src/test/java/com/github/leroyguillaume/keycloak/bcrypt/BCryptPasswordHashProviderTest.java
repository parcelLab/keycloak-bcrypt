package com.github.leroyguillaume.keycloak.bcrypt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.models.credential.PasswordCredentialModel;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.google.common.hash.Hashing;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;

class BCryptPasswordHashProviderTest {
    private final int iterations = 10;
    private final String id = "bcrypt";
    private final BCryptPasswordHashProvider provider = new BCryptPasswordHashProvider(id, iterations);

    @Test
    @DisplayName("Should hash the password successfully")
    void shouldHashThePasswordSuccessfully() {
        String rawPassword = "test";
        String hashedPassword = provider.encode(rawPassword, iterations);
        PasswordCredentialModel model = PasswordCredentialModel.createFromValues(id, new byte[0], iterations, hashedPassword);

        assertNotNull(hashedPassword);
        assertTrue(provider.verify(rawPassword, model));
    }

    @Test
    @DisplayName("Should verify the password successfully.")
    void shouldVerifyTheHashSuccessfully() {
        String rawPassword = "jqy*VFN.rkn5xcu@ape";
        String hashedPassword = provider.encode(rawPassword, iterations);
        String rawPasswordAsSHA256String = Hashing.sha256().hashString(rawPassword, StandardCharsets.UTF_8).toString();
        String rawPasswordClone = rawPassword;
        String rawPasswordCloneAsSHA256String = Hashing.sha256().hashString(rawPasswordClone, StandardCharsets.UTF_8).toString();        
        
        final BCrypt.Result verifyHashedPasswordResult = BCrypt.verifyer(BCrypt.Version.VERSION_2B).verify(rawPasswordAsSHA256String.toCharArray(), hashedPassword.toCharArray());
        assertTrue(verifyHashedPasswordResult.verified);

        final BCrypt.Result verifySamePasswordResult = BCrypt.verifyer(BCrypt.Version.VERSION_2B).verify(rawPasswordCloneAsSHA256String.toCharArray(), hashedPassword.toCharArray());
        assertTrue(verifySamePasswordResult.verified);

        final BCrypt.Result verifyHashedPasswordDBValueResult = BCrypt.verifyer(BCrypt.Version.VERSION_2B).verify(rawPasswordAsSHA256String.toCharArray(), "$2b$10$INBHg4Z0.Bdpsj6ir0/17.5J19z79AyAiwpS24P1ieX6gO8Uzw9uO".toCharArray());
        assertTrue(verifyHashedPasswordDBValueResult.verified);
    }
}

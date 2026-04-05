package com.diegoanyosa.authservice.repository;

import com.diegoanyosa.authservice.model.OAuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OAuthProviderRepository extends JpaRepository<OAuthProvider, UUID> {
    Optional<OAuthProvider> findByProviderAndProviderUserId(String provider, String providerUserId);
}

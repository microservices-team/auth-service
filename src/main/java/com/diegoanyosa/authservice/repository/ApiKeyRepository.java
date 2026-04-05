package com.diegoanyosa.authservice.repository;

import com.diegoanyosa.authservice.model.ApiKey;
import com.diegoanyosa.authservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {
    List<ApiKey>    findByUserAndActiveTrue(User user);
    Optional<ApiKey> findByKeyHash(String keyHash);
}

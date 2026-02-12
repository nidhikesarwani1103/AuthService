package dev.nidhi.oauthimplementation.repositories;

import dev.nidhi.oauthimplementation.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

}

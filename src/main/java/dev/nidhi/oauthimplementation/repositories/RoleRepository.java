package dev.nidhi.oauthimplementation.repositories;

import dev.nidhi.oauthimplementation.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

}

package dev.nidhi.oauthimplementation.dtos;

import dev.nidhi.oauthimplementation.models.Role;
import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Component;

import java.util.List;

@Setter
@Getter
public class UserDTO {
    private Long id;
    private String username;
    private String email;
    private List<Role> roles;

    public UserDTO(Long id, String username, String email, List<Role> roles) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }
}

package dev.nidhi.oauthimplementation.models;

import dev.nidhi.oauthimplementation.dtos.UserDTO;
import jakarta.persistence.Entity;
import jakarta.persistence.ManyToMany;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Entity
@Getter
@Setter
public class User extends  BaseModel{

    private String username;
    private String email;
    private String password;
    @ManyToMany
    private List<Role> roles;

    public UserDTO convertToUserDTO() {
        return new UserDTO(this.getId(),
                           this.getUsername(),
                           this.getEmail(), this.getRoles());
    }
}

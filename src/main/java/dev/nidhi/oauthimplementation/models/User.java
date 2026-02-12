package dev.nidhi.oauthimplementation.models;

import dev.nidhi.oauthimplementation.dtos.UserDTO;
import jakarta.persistence.Entity;
import jakarta.persistence.ManyToMany;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;
import java.util.List;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class User extends  BaseModel{

    private String username;
    private String email;
    private String password;
    @ManyToMany
    private List<Role> roles;

    public User(String username, String email, String password,
                List<Role> roles, Date createdAt, Date updatedAt, State state) {
        super.setCreatedAt(createdAt);
        super.setUpdatedAt(updatedAt);
        super.setState(state);
        this.username = username;
        this.email = email;
        this.roles = roles;
    }

    public UserDTO convertToUserDTO() {
        return new UserDTO(this.getId(),
                           this.getUsername(),
                           this.getEmail(), this.getRoles());
    }
}

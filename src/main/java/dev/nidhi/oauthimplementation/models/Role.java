package dev.nidhi.oauthimplementation.models;

import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class Role extends BaseModel{

    private String name;

    public Role(String name, Date createdAt, Date updatedAt, State state) {
        this.name = name;
        super.setCreatedAt(createdAt);
        super.setUpdatedAt(updatedAt);
        super.setState(state);
    }
}

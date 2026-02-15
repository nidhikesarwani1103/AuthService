package dev.nidhi.oauthimplementation.models;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class Session extends BaseModel{

    @Column(columnDefinition = "TEXT")
    private String token;

    @ManyToOne
    private User user;

    public Session(String token, User user, State state) {
        this.token = token;
        this.user = user;
        this.setState(state);
    }
}

package dev.nidhi.oauthimplementation.service;

import dev.nidhi.oauthimplementation.models.User;
import dev.nidhi.oauthimplementation.pojos.UserToken;

public interface IAuthService {

    User signup(String username, String email, String password);
    UserToken login(String email, String password);
    Boolean validateToken(String token);
}

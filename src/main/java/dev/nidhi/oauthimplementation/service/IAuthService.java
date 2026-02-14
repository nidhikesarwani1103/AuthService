package dev.nidhi.oauthimplementation.service;

import dev.nidhi.oauthimplementation.models.User;
import org.antlr.v4.runtime.misc.Pair;

public interface IAuthService {

    User signup(String username, String email, String password);
    Pair<User, String> login(String username, String password);
    Boolean validateToken(String token);
}

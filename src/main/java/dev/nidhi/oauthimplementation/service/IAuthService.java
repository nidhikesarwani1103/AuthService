package dev.nidhi.oauthimplementation.service;

import dev.nidhi.oauthimplementation.models.User;
import org.springframework.stereotype.Service;

public interface IAuthService {

    User signup(String username, String email, String password);
    User login(String username, String password);
}

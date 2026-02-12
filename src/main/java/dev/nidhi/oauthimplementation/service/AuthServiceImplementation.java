package dev.nidhi.oauthimplementation.service;

import dev.nidhi.oauthimplementation.models.User;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImplementation implements IAuthService {
    @Override
    public User signup(String username, String email, String password) { return null; }

    @Override
    public User login(String username, String password) { return null; }
}

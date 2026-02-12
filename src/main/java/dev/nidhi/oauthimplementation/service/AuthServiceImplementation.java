package dev.nidhi.oauthimplementation.service;

import dev.nidhi.oauthimplementation.exceptions.InvalidCredentialsException;
import dev.nidhi.oauthimplementation.exceptions.UserAlreadyExistsException;
import dev.nidhi.oauthimplementation.exceptions.UserNotRegisteredException;
import dev.nidhi.oauthimplementation.models.Role;
import dev.nidhi.oauthimplementation.models.State;
import dev.nidhi.oauthimplementation.models.User;
import dev.nidhi.oauthimplementation.repositories.RoleRepository;
import dev.nidhi.oauthimplementation.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class AuthServiceImplementation implements IAuthService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;

    @Override
    public User signup(String username, String email, String password) {
        // Every user should register with unique by email and username, so we need to check if a user
        // with the same email or username already exists in the database before creating a new user.
        Optional<User> OptionalUser = userRepository.findByEmail(email);
        if(OptionalUser.isPresent()){
            throw new UserAlreadyExistsException("User with email " + email + " already exists.");
        }
        // set the default role for the user as "USER"
        Role role;
        Optional<Role> optionalRole = roleRepository.findByName("DEFAULT");

        if(optionalRole.isEmpty()){
            role = new Role("DEFAULT", new Date(), new Date(), State.ACTIVE);
            roleRepository.save(role);
        } else {
            role = optionalRole.get();
        }

        User user = new User(username, email, password, List.of(role),
                             new Date(), new Date(), State.ACTIVE);

        return userRepository.save(user);
    }

    @Override
    public User login(String username, String password) {

        Optional<User> optionalUser = userRepository.findByUsername(username);
        if(optionalUser.isEmpty()){
            throw new UserNotRegisteredException("User with username " + username +
                    " is not registered");
        }

        if(!optionalUser.get().getPassword().equals(password)){
             throw new InvalidCredentialsException("Invalid password for username " + username);
        }

        return optionalUser.get();
    }
}

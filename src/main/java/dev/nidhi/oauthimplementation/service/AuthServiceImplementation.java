package dev.nidhi.oauthimplementation.service;

import dev.nidhi.oauthimplementation.exceptions.IncorrectPasswordException;
import dev.nidhi.oauthimplementation.exceptions.InvalidCredentialsException;
import dev.nidhi.oauthimplementation.exceptions.UserAlreadyExistsException;
import dev.nidhi.oauthimplementation.exceptions.UserNotRegisteredException;
import dev.nidhi.oauthimplementation.models.Role;
import dev.nidhi.oauthimplementation.models.Session;
import dev.nidhi.oauthimplementation.models.State;
import dev.nidhi.oauthimplementation.models.User;
import dev.nidhi.oauthimplementation.pojos.UserToken;
import dev.nidhi.oauthimplementation.repositories.RoleRepository;
import dev.nidhi.oauthimplementation.repositories.SessionRepository;
import dev.nidhi.oauthimplementation.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.antlr.v4.runtime.misc.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.util.*;

@Service
public class AuthServiceImplementation implements IAuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private SessionRepository sessionRepository;

    // defined in configs/AuthConfig.java
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private static final Logger LOG =
            LoggerFactory.getLogger(AuthServiceImplementation.class);

    /*
        Generating secret key again will create a new key, we don't want that
         So we need to make secret key as singleton and use the same key for
         both generating and validating the token
         Define a bean for secret key in the configuration class and autowire it here

     */
    @Autowired
    private SecretKey secretKey;

    @Override
    public User signup(String username, String email, String password) {
        // Every user should register with unique by email and username, so we need to check if a user
        // with the same email or username already exists in the database before creating a new user.
        Optional<User> OptionalUser = userRepository.findByEmail(email);
        if(OptionalUser.isPresent()){
            LOG.debug("User Already Registered with email: {}", email);
            throw new UserAlreadyExistsException("User with email " + email + " already exists.");
        }
        // set the default role for the user as "USER"
        Role role;
        Optional<Role> optionalRole = roleRepository.findByName("DEFAULT");

        if(optionalRole.isEmpty()){
            LOG.debug("Setting up default role for the user");
            role = new Role("DEFAULT", new Date(), new Date(), State.ACTIVE);
            roleRepository.save(role);
        } else {
            role = optionalRole.get();
        }

        User user = new User(username, email, bCryptPasswordEncoder.encode(password),
                List.of(role), new Date(), new Date(), State.ACTIVE);
        userRepository.save(user);
        LOG.debug("User Details fetched from db: "+
                userRepository.findByEmail(email));
        return user;
    }



    @Override
    public UserToken login(String email, String password) {
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if(optionalUser.isEmpty()){
            LOG.debug("User not registered with email: {}", email);
            throw new UserNotRegisteredException("Please register first");
        }

        User user = optionalUser.get();

        if(bCryptPasswordEncoder.matches(password, user.getPassword())){

            LOG.debug("Password matched, generating token for the user: {}", email);

            String token = prepareJwtToken(optionalUser.get());

            LOG.debug("Generated token for the user: {} is {}", email, token);

            createNewSession(user, token);

            LOG.debug("Fetched session details from db: {}", sessionRepository.findByToken(token));

            return new UserToken(user, token);
        }
        else{
            throw new IncorrectPasswordException("Incorrect password entered");
        }
    }

    @Override
    public Boolean validateToken(String token) {

        // We need to check if the token is present in the session table
        Optional<Session> optionalSession = sessionRepository.findByToken(token);
        if(optionalSession.isEmpty()){
            LOG.debug("Token not found in session table");
            return false;
        }
        // We need the secret key and algorithm to validate the token
        JwtParser jwtParser = Jwts.parser().verifyWith(secretKey).build();
        Claims claims = jwtParser.parseSignedClaims(token).getPayload();

        LOG.debug("Claim: {}", claims);

        Long expiryTime = (Long) claims.get("exp");
        Long nowInMills = System.currentTimeMillis();

        if(nowInMills > expiryTime)
        {
            LOG.debug("Token is expired");
            Session session = optionalSession.get();
            session.setState(State.INACTIVE);
            sessionRepository.save(session);
            LOG.debug("Session is saved as inactive");
            LOG.debug("Session fetched from db: {}",
                    sessionRepository.findByToken(token));
            return false;
        }
        LOG.debug("Token is valid");
        return true;
    }

    public void createNewSession(User user, String token){
        Session session = new Session();
        session.setToken(token);
        session.setUser(user);
        session.setState(State.ACTIVE);
        LOG.debug("Session details: {}", session);
        sessionRepository.save(session);
    }

/*
 login api should generate the JWT  token
 Payload is the most important also referred as claims,
   which contains the user information and the token expiration time and other relevant data.
 Header contains the type of token and the signing algorithm used to sign the token.
 Signature is used to verify the authenticity of the token and ensure that
   it has not been tampered with.

 Which data type?

 Map<String, Object> claims = new HashMap<>(); Where key represents the claim name and value
  represents the claim value.

  Claim value (payload):
     1. issuedAt: (iat)
     2. exp: (exp)
     3. userid (userId)
     4. issuedBy (iss)
     5. scope (scope)

*/
    private String prepareJwtToken(User user){
        Map<String, Object> payload = new HashMap<>();
        payload.put("iat", System.currentTimeMillis());
        payload.put("exp", System.currentTimeMillis()+ 10000000); // 24 hours
        payload.put("iss", "Nidhi");
        payload.put("userId", user.getId());
        payload.put("scope", user.getRoles());

        // Now we need header(algorithm) and signature to generate the JWT token

        //Algorithm
        MacAlgorithm macAlgorithm = Jwts.SIG.HS256;
        String token = Jwts.builder().
                claims(payload)
                .signWith(secretKey)
                .compact();

        return token;
    }
}

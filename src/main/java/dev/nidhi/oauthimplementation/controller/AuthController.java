package dev.nidhi.oauthimplementation.controller;

import dev.nidhi.oauthimplementation.dtos.LoginRequestDTO;
import dev.nidhi.oauthimplementation.dtos.SignupRequestDTO;
import dev.nidhi.oauthimplementation.dtos.UserDTO;
import dev.nidhi.oauthimplementation.dtos.ValidateTokenDTO;
import dev.nidhi.oauthimplementation.models.User;
import dev.nidhi.oauthimplementation.service.IAuthService;
import org.antlr.v4.runtime.misc.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

      /*
      1. Signup Endpoint: This endpoint will handle user registration.
         It will accept user details (like username, password, email) and create a new user in the database.
         - Request Type: POST
                 /auth/signup
         - Return Type: ResponseEntity<UserDTO> (indicating success or failure of registration)
               - 200 OK: User registered successfully, return the created user details.
               - 400 Bad Request: Invalid input data, return error message.
         - Request Body: SignupRequestDTO (a DTO containing user registration details)
               - user, email, password

         2. Login Endpoint: This endpoint will handle user authentication.
            It will accept user credentials (like username and password) and authenticate the user.
            - Request Type: POST
                    /auth/login
            - Return Type: ResponseEntity<UserDTO> (indicating success or failure of authentication)
                  - 200 OK: Authentication successful, return a JWT token or session information.
                  - 401 Unauthorized: Authentication failed, return error message.
            - Request Body: LoginRequestDTO (a DTO containing user login credentials)
                    - user, password

       */
    @Autowired
    private IAuthService authService;

    @PostMapping("/signup")
    ResponseEntity<UserDTO> signup(@RequestBody SignupRequestDTO signupRequestDTO) {
        // Implement user registration logic here
        // Validate input, create user, save to database, and return appropriate response
        /*
          {
            "username":"Nidhi",
            "password":"Nidhi123",
            "email":"nidhi@gmail.com"
          }
         */
       try{
           User user = authService.signup(signupRequestDTO.getUsername(),
                   signupRequestDTO.getEmail(),
                   signupRequestDTO.getPassword());

           return new ResponseEntity<>(user.convertToUserDTO(), HttpStatus.CREATED);
       }
         catch (Exception e){
              return new ResponseEntity<>((HttpHeaders) null, HttpStatus.BAD_REQUEST);
         }
    }

    @PostMapping("/login")
    ResponseEntity<UserDTO> login(@RequestBody LoginRequestDTO loginRequestDTO){
        // Implement user authentication logic here
        // Validate credentials, authenticate user, and return appropriate response
        /*
        {
            "username":"Kavya",
            "password":"Kavya123"
        }
         */
        try{
            System.out.println("landed here");
            Pair<User, String> response = authService.login(loginRequestDTO.getUsername(),
                    loginRequestDTO.getPassword());

            // We have to set token in the header
            // Headers are represented as MultiValue Map, the client will save this token as cookies

            MultiValueMap <String, String> headers = new LinkedMultiValueMap<>();
            headers.add(HttpHeaders.COOKIE, response.b);
            HttpHeaders httpHeaders = new HttpHeaders(headers);
            return new ResponseEntity<>(response.a.convertToUserDTO(),
                                        httpHeaders,
                                        HttpStatus.OK);
        }
        catch (Exception e){
            return new ResponseEntity<>((HttpHeaders) null, HttpStatus.UNAUTHORIZED);
        }
    }

    /*
    API to validate the JWT token and get the user details based on the token,
    this will be used in the frontend to check if the user is logged in or not,
    and to get the user details to show in the front-end.
    -Request Type: POST
    -Endpoint: /validate-token
    -Input Parameter: JWT token
    -Response Type: ResponseEntity<UserDTO>
        Success: 200, with user details
        Failure: 401, with error message
     */

    @PostMapping("/validate-token")
    public ResponseEntity<String> validateToken(@RequestBody ValidateTokenDTO validateTokenDTO){

       Boolean result = authService.validateToken(validateTokenDTO.getToken());
       if(result){
           return new ResponseEntity<>("Token is valid", HttpStatus.OK);
       }
       else {
           return new ResponseEntity<>("Please login again", HttpStatus.FORBIDDEN);
       }
    }

}

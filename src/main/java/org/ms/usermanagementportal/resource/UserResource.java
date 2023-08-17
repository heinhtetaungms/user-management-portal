package org.ms.usermanagementportal.resource;

import jakarta.mail.MessagingException;
import org.ms.usermanagementportal.configuration.UserPrincipal;
import org.ms.usermanagementportal.exception.domain.*;
import org.ms.usermanagementportal.model.User;
import org.ms.usermanagementportal.response.HttpResponse;
import org.ms.usermanagementportal.service.UserService;
import org.ms.usermanagementportal.utility.JWTTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static org.ms.usermanagementportal.constant.FileConstant.*;
import static org.ms.usermanagementportal.constant.SecurityConstant.JWT_TOKEN_HEADER;
import static org.springframework.http.HttpStatus.NO_CONTENT;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.IMAGE_JPEG_VALUE;
import static org.springframework.http.MediaType.IMAGE_PNG_VALUE;

@RestController
@RequestMapping("/user")
public class UserResource extends ExceptionHandling {

    public static final String EMAIL_SENT = "An Email with new password was sent to : ";
    public static final String USER_DELETED_SUCCESSFULLY = "User deleted successfully.";
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JWTTokenProvider jwtTokenProvider;
    @Autowired
    public UserResource(UserService userService, AuthenticationManager authenticationManager, JWTTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user) {
        authenticate(user.getUsername(), user.getPassword());
        User loginUser = userService.findUserByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        return new ResponseEntity<>(loginUser, jwtHeader, OK);
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException {
        User newUser =userService.register(user.getFirstName(), user.getLastName(), user.getUsername(), user.getEmail());
        return new ResponseEntity<>(newUser, OK);
    }

    @PostMapping("/add")
    public ResponseEntity<User> addNewUser(@RequestParam("firstName")String firstName,
                                           @RequestParam("lastName")String lastName,
                                           @RequestParam("username")String userName,
                                           @RequestParam("email")String email,
                                           @RequestParam("role")String role,
                                           @RequestParam("isActive")String isActive,
                                           @RequestParam("isNonLocked")String isNonLocked,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage
                                           ) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {
        User newUser = userService.addNewUser(firstName, lastName, userName, email, role, Boolean.parseBoolean(isActive), Boolean.parseBoolean(isNonLocked), profileImage);
        return new ResponseEntity<>(newUser, OK);
    }

    @PostMapping("/update")
    public ResponseEntity<User> updateUser(@RequestParam("currentUserName")String currentUsername,
                                           @RequestParam("firstName")String firstName,
                                           @RequestParam("lastName")String lastName,
                                           @RequestParam("username")String userName,
                                           @RequestParam("email")String email,
                                           @RequestParam("role")String role,
                                           @RequestParam("isActive")String isActive,
                                           @RequestParam("isNonLocked")String isNonLocked,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage
    ) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {
        User updateUser = userService.updateUser(currentUsername, firstName, lastName, userName, email, role, Boolean.parseBoolean(isActive), Boolean.parseBoolean(isNonLocked), profileImage);
        return new ResponseEntity<>(updateUser, OK);
    }

    @GetMapping("/find/{username}")
    public ResponseEntity<User> getUser(@PathVariable("username")String userName) {
        User user = userService.findUserByUsername(userName);
        return new ResponseEntity<>(user, OK);
    }

    @GetMapping("/list")
    public ResponseEntity<List<User>> getUsers() {
        List<User> users = userService.getUsers();
        return new ResponseEntity<>(users, OK);
    }

    @GetMapping("/resetPassword/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email")String email) throws EmailNotFoundException {
        userService.resetPassword(email);
        return response(OK, EMAIL_SENT + email);
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAnyAuthority('user:delete')")
    public ResponseEntity<HttpResponse> deleteUser(@PathVariable("id")long id) {
        userService.deleteUser(id);
        return response(NO_CONTENT, USER_DELETED_SUCCESSFULLY);
    }

    @GetMapping(value = "/image/{userName}/{fileName}", produces = {IMAGE_JPEG_VALUE, IMAGE_PNG_VALUE})
    public byte[] getProfileImage(@PathVariable("username")String userName, @PathVariable("fileName")String fileName) throws IOException {
        return Files.readAllBytes(Paths.get(USER_FOLDER + userName + FORWARD_SLASH + fileName));
    }

    @GetMapping(value = "/image/profile/{username}", produces = {IMAGE_JPEG_VALUE, IMAGE_PNG_VALUE})
    public byte[] getTempProfileImage(@PathVariable("username")String userName) throws IOException {
        URL url = new URL(TEMP_PROFILE_IMAGE_BASE_URL + userName);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try(InputStream inputStream = url.openStream()) {
            int byteRead;
            byte[] chunk =new byte[1024];
            while ((byteRead = inputStream.read(chunk)) > 0) {
                baos.write(chunk, 0, byteRead);
            }
        }
        return baos.toByteArray();
    }

    private ResponseEntity<HttpResponse> response(HttpStatus httpStatus, String message) {
        HttpResponse body = new HttpResponse(httpStatus.value(), httpStatus, httpStatus.getReasonPhrase().toUpperCase(), message.toUpperCase());
        return new ResponseEntity<>(body, httpStatus);
    }

    @PostMapping("/updateProfileImage")
    public ResponseEntity<User> updateProfileImage(
                                           @RequestParam("username")String userName,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {
        User user = userService.updateProfileImage(userName, profileImage);
        return new ResponseEntity<>(user, OK);
    }

    private HttpHeaders getJwtHeader(UserPrincipal user) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(user));
        return headers;
    }

    private void authenticate(String userName, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userName, password));
    }


}

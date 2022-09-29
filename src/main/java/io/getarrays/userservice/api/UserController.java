package io.getarrays.userservice.api;

import io.getarrays.userservice.domain.User;
import io.getarrays.userservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {
    private  final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>>getUser() {
        return ResponseEntity.ok().body(userService.getUser());
    }

}

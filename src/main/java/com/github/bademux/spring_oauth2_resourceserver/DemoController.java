package com.github.bademux.spring_oauth2_resourceserver;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

@RestController
@RequestMapping(Application.API_PREFIX)
@RequiredArgsConstructor
public class DemoController {

    @RolesAllowed("demo-admin")
    @GetMapping("/v1/demo")
    public ResponseEntity<?> demo() {
        return ResponseEntity.ok().build();
    }

}

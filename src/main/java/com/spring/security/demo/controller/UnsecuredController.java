package com.spring.security.demo.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/permitted")
public class UnsecuredController {

    @GetMapping(produces = "application/json")
    public String greeter() {
        return "I am permiiteed endpoint.";
    }
}

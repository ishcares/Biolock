package com.scamshield.biolock.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class RootController {

    @GetMapping("/")
    public ResponseEntity<Map<String, String>> root() {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("service", "BioLock Zero-Trust Eng ine");
        map.put("status", "ONLINE");
        map.put("demoUrl", "/api/demo/run");
        map.put("githubRepository", "https://github.com/ishcares/Biolock");
        return ResponseEntity.ok(map);
    }
}

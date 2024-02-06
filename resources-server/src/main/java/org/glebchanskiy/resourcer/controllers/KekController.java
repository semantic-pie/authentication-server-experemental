package org.glebchanskiy.resourcer.controllers;

import org.glebchanskiy.resourcer.models.KekResource;
import org.glebchanskiy.resourcer.repositories.KekResourceRepository;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
@CrossOrigin(origins = "http://localhost:3000")
public class KekController {

 private final KekResourceRepository kekResourceRepository;

 @GetMapping("/kek")
 Iterable<KekResource> kek() {
  return kekResourceRepository.findAll();
 }

}

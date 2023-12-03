package com.example.spring.security.oauth2.controller;

import com.example.spring.security.oauth2.model.Person;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/persons")
public class PersonController {
    private static List<Person> persons = new ArrayList();
    static {
        Person p1 = new Person("Jack", "Smith");
        Person p2 = new Person("Lucas", "Derrik");
        Person p3 = new Person("Andy", "Miller");
        persons.add(p1);
        persons.add(p2);
        persons.add(p3);
    }
    @GetMapping
    public String getAllPersons(Model model) {
        model.addAttribute("persons", persons);
        return "persons-view";
    }
}

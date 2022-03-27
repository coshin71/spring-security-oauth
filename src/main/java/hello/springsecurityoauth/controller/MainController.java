package hello.springsecurityoauth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class MainController {

    @RequestMapping("/login")
    public String login(){
        return "login/index";
    }

    @RequestMapping("/user")
    public String user(){
        return "user/index";
    }

}

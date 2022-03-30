package hello.springsecurityoauth.controller;

import hello.springsecurityoauth.config.auth.PrincipalDetails;
import hello.springsecurityoauth.domain.User;
import hello.springsecurityoauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class MainController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String testLogin(Authentication authentication,
                                          @AuthenticationPrincipal PrincipalDetails userDetails) {
        System.out.println("=================== /test/login ===================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principalDetails = " + principalDetails.getUser());

        System.out.println("userDetails.getUser() = " + userDetails.getUser());
        return "세션 정보 확인";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(Authentication authentication,
                                          @AuthenticationPrincipal OAuth2User oAuth) {
        System.out.println("=================== /test/oauth/login ===================");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("principalDetails = " + oAuth2User.getAttributes());

        System.out.println("userDetails.getUser() = " + oAuth2User.getAttributes());
        return "OAuth 세션 정보 확인";
    }

    @GetMapping("/")
    public String home(){
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails.getUser() = " + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }
    @GetMapping("/signup")
    public String signupForm() {
        return "signupForm";
    }

    @PostMapping("/signup")
    public String signup(@ModelAttribute("user") User user) {
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = passwordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);

        return "redirect:/loginForm";
    }

    @Secured({"ROLE_ADMIN", "ROLE_MANAGER"})
    @GetMapping("/test")
    public @ResponseBody String test() {
        return "테스트";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/hello")
    public @ResponseBody String hello() {
        return "hello";
    }
}

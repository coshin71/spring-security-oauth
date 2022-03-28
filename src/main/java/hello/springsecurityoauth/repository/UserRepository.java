package hello.springsecurityoauth.repository;

import hello.springsecurityoauth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
}

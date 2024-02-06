package org.glebchanskiy.authserver.repositories;

import java.util.Optional;

import org.glebchanskiy.authserver.models.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {
 Optional<User> findByUsername(String username);
}

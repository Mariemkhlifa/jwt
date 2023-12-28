package usersmicroservice.Repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import usersmicroservice.entities.User;


public interface UserRepository  extends JpaRepository<User, Long> {
	User findByUsername(String username);
	User findUserByEmail(String email);

	 
	
	/*Optional<User> findByUsername(String username);*/
	 User findByEmailAndMatricule(String email, String matricule);
	 User findByEmailAndPassword(String email, String password);
	User findByMatricule(String matricule);	
	Optional<User> findByEmail(String email);

	


 
}

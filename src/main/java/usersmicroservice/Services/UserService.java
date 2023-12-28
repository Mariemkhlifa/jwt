package usersmicroservice.Services;

import java.util.List;

import usersmicroservice.entities.Role;
import usersmicroservice.entities.User;
import usersmicroservice.register.RegistrationRequest;

public interface UserService {
	public User getUserByMailAndMatricule(String email, String matricule);
	public List<User> getAllUser();
	public User findUserById(Long user_id);
	public User updateUser(User user);
	public void deleteUser(Long user_id);
	public void deleteUserRole(Long user_id);
	public User updateUserById(Long user_id, User updatedUser);
	public User getUserByMailAndPassword(String email, String password);
	public User findUserByMatricule(String matricule);

	User createUser(User user);
	User  regirterUser(RegistrationRequest request);
	User findUserByUsername (String username);
	Role addRole(Role role);
	User addRoleToUser(String username, String rolename);
	 User validateToken(String code) ;
	 User saveUser(User user);
	 User findUserByEmail(  String email);
	 
		

}

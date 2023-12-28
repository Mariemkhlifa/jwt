package usersmicroservice.Services;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;



import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import usersmicroservice.Repositories.RoleRepository;
import usersmicroservice.Repositories.UserRepository;
import usersmicroservice.entities.Role;
import usersmicroservice.entities.User;
import usersmicroservice.register.EmailAlreadyExistsException;
import usersmicroservice.register.ExpiredTokenException;
import usersmicroservice.register.InvalidTokenException;
import usersmicroservice.register.RegistrationRequest;
import usersmicroservice.register.VerificationToken;
import usersmicroservice.register.VerificationTokenRepository;


@Transactional
@Service
public class UserServicempl implements UserService{
@Autowired
UserRepository userRep;

@Autowired
RoleRepository roleRep;

@Autowired
BCryptPasswordEncoder bCryptPasswordEncoder;

@Autowired
VerificationTokenRepository verificationTokenRepo;

@PersistenceContext
private EntityManager entityManager;









@Override
public User createUser(User user) {
	
	user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
	return userRep.save(user);
}

@Override
public User saveUser(User user) {
	return userRep.save(user);

}



@Override
public User regirterUser(RegistrationRequest request) {
	
	Optional<User>  optionalUser = userRep.findByEmail(request.getEmail());
	if(optionalUser.isPresent())
		throw new EmailAlreadyExistsException("Email déjà existant!");
	
	User newUser = new User();
	newUser.setUsername(request.getUsername());
	newUser.setEmail(request.getEmail());
	newUser.setLastName(request.getLastName());
	newUser.setMatricule(request.getMatricule());
	newUser.setTel(request.getTel());
	newUser.setSexe(request.getSexe());
	newUser.setDateNaissance(request.getDateNaissance());

	
	newUser.setPassword( bCryptPasswordEncoder.encode( request.getPassword() )  );
	
	userRep.save(newUser);
	
	Role r = roleRep.findByRole("USER");
	List<Role> roles = new ArrayList<>();
	roles.add(r);
	newUser.setRoles(roles);
	
	//génére le code secret
	 String code = this.generateCode();

	 VerificationToken token = new VerificationToken(code, newUser);
	 verificationTokenRepo.save(token);
	
	return userRep.save(newUser);

	
 
}

private String generateCode() {
	 Random random = new Random();
	 Integer code = 100000 + random.nextInt(900000);

	 return code.toString();

}



@Override
public User addRoleToUser(String username, String rolename) {
	User usr = userRep.findByUsername(username);
	Role r = roleRep.findByRole(rolename);
	usr.getRoles().add(r);
	return usr;
}

@Override
public Role addRole(Role role) {
	return roleRep.save(role);
}
@Override
public User findUserByUsername(String username) {
	return userRep.findByUsername(username);
	}
@Override
public User getUserByMailAndMatricule(String email, String matricule) {
    return userRep.findByEmailAndMatricule(email, matricule);

}
@Override
public List<User> getAllUser() {
	return userRep.findAll();

}
@Override
public User findUserById(Long user_id) {
	Optional<User> utOptional = userRep.findById(user_id); 
	
	if(utOptional.isEmpty() ) {
		return null;
	}else {
		return utOptional.get();
	}
}
@Override
public User updateUser(User user) {
	Optional<User> utOptional = userRep.findById(user.getUser_id()); 
	if(utOptional.isEmpty() ) {
		return null;
	}else {
		return userRep.save(user);
	}
}


  /* @Override
    public void deleteUserRole(Long user_id) {
        Optional<User> userOptional = userRep.findById(user_id);

        if (userOptional.isPresent()) {
            User user = userOptional.get();

            // Supprimer l'utilisateur et les relations dans la table de jointure
            user.getRoles().clear(); // Supprime toutes les relations ManyToMany
            userRep.deleteById(user_id);
        }
        
        System.out.println("user deleted");
    

}*/
    

  @Override
public void deleteUser(Long user_id) {
    User user = entityManager.find(User.class, user_id);

    if (user != null) {
        // Remove VerificationToken (OneToOne relationship)
        VerificationToken verificationToken = user.getVerificationToken();
        if (verificationToken != null) {
            entityManager.remove(verificationToken);
        }

        // Remove Roles (ManyToMany relationship)
        List<Role> roles = user.getRoles();
        if (roles != null) {
            user.setRoles(null); // This disassociates roles from the user
            userRep.deleteById(user_id); // Remove the user from the role's user list
            System.out.println("User deleted");
        } else {
            System.out.println("User not found");
        }
        }

        // Remove the User
        entityManager.remove(user);
    }


@Override
public User updateUserById(Long user_id, User updatedUser) {
	Optional<User> userOptional = userRep.findById(user_id);
    if (userOptional.isPresent()) {
        User existingUser = userOptional.get();
        

        if (updatedUser.getUsername() != null) {
            existingUser.setUsername(updatedUser.getUsername());
        }
        
        if (updatedUser.getLastName() != null) {
            existingUser.setLastName(updatedUser.getLastName());
        }
        
        if (updatedUser.getPassword() != null) {
            existingUser.setPassword(updatedUser.getPassword());
        }
        
        if (updatedUser.getTel() != null) {
            existingUser.setTel(updatedUser.getTel());
        }
        
        if (updatedUser.getSexe() != null) {
            existingUser.setSexe(updatedUser.getSexe());
        }
        
        if (updatedUser.getEmail() != null) {
            existingUser.setEmail(updatedUser.getEmail());
        }
        
        if (updatedUser.getDateNaissance() != null) {
            existingUser.setDateNaissance(updatedUser.getDateNaissance());
        }
        
        if (updatedUser.getMatricule() == null) {
            updatedUser.setMatricule(existingUser.getMatricule());
        }
        // Save the updated user
        return userRep.save(existingUser);
    } else {
        throw new NoSuchElementException("Utilisateur non trouvé avec l'ID : " + user_id);
    }
    
}
@Override
public User getUserByMailAndPassword(String email, String password) {
    return userRep.findByEmailAndPassword(email, password);

}
@Override
public User findUserByMatricule(String matricule) {
	return userRep.findByMatricule(matricule);

}


@Override
public User validateToken(String code) {
	VerificationToken token = verificationTokenRepo.findByToken(code);
	
	if(token == null){
		throw new InvalidTokenException("Invalid Token !!!!!!!");
	}

	User user = token.getUser();
	
	Calendar calendar = Calendar.getInstance();
	
	if ((token.getExpirationTime().getTime() - calendar.getTime().getTime()) <= 0){
		verificationTokenRepo.delete(token);
		throw new ExpiredTokenException("expired Token");
	}
	

	return user;
}

@Override
public User findUserByEmail(String email) {
	return userRep.findUserByEmail(email);
}

@Override
public void deleteUserRole(Long user_id) {
    Optional<User> userOptional = userRep.findById(user_id);

    if (userOptional.isPresent()) {
        User user = userOptional.get();

        // Supprimer l'utilisateur et les relations dans la table de jointure
        user.getRoles().clear(); // Supprime toutes les relations ManyToMany

        // Supprimer le token de vérification s'il existe
        if (user.getVerificationToken() != null) {
            verificationTokenRepo.deleteById(user.getVerificationToken().getId());
        }

        // Supprimer l'utilisateur
        userRep.deleteById(user_id);

        System.out.println("User deleted");
    } else {
        System.out.println("User not found");
    }	
}





}

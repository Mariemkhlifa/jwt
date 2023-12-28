package usersmicroservice.controllers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import usersmicroservice.Repositories.UserRepository;
import usersmicroservice.Services.UserService;
import usersmicroservice.entities.ApiResponse;
import usersmicroservice.entities.User;
import usersmicroservice.register.RegistrationRequest;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
public class UserRestController {
	
	@Autowired
	UserRepository userRep;
	

	@Autowired
	private UserService userService ;
	
	 @Autowired
	    private JavaMailSender javaMailSender;
	 
	 @Autowired
	 private BCryptPasswordEncoder bCryptPasswordEncoder;
	 
	 
	 

		@RequestMapping(path = "all",method = RequestMethod.GET)
	   public List<User> getAllUsers() {
		return userRep.findAll();
	 }
	
	
    @GetMapping("find/{user_id}")
	public ResponseEntity<User> findUserById(@PathVariable Long user_id)
	{
		User user= userService.findUserById(user_id);
		
		
		if(user==null)
		{
			return new ResponseEntity<User>(HttpStatus.NO_CONTENT);
		}else {
			return new ResponseEntity<User>(user,HttpStatus.OK);
		}
	}
	
	private void sendRegistrationEmail(User user, String plainTextPassword) {
	    MimeMessage message = javaMailSender.createMimeMessage();
	    MimeMessageHelper helper = new MimeMessageHelper(message);

	    try {
	        helper.setTo(user.getEmail());
	        helper.setSubject("Welcome to our platform!");
	        String emailContent = "Thank you for registering.\n\n";
	        emailContent += "Here are your login credentials:\n";
	        emailContent += "Email: " + user.getEmail() + "\n";
	        emailContent += "Password: " +  plainTextPassword + "\n";

	        helper.setText(emailContent);

	        javaMailSender.send(message);
	    } catch (MessagingException e) {
	        e.printStackTrace(); 
	    }
	}
	
	
	 @PostMapping("/register")
	    public ResponseEntity<String> register(@RequestBody RegistrationRequest request) {
	        User createdUser = userService.regirterUser(request);

	        if (createdUser != null) {
	            // Send the registration email with the uncrypted email address
	            sendRegistrationEmail(createdUser, request.getPassword());
	            return ResponseEntity.ok("User created successfully, and registration email sent.");
	        } else {
	            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to create user.");
	        }
	    }
	 

	
	 
	 
	 
	@DeleteMapping(path="/deleteUser/{user_id}")
	public void deleteUser(@PathVariable Long user_id) {
	    userService.deleteUser(user_id);
	}
	
	
	@PutMapping(path="/update/{user_id}")
	    public ResponseEntity<User> updateUserById(@PathVariable Long user_id, @RequestBody User updatedUser) {
	        User updatedUtilisateur = userService.updateUserById(user_id, updatedUser);
	        return ResponseEntity.ok(updatedUtilisateur);
	    }
	 
	 
	 @GetMapping("/recuperer/{email}/{matricule}")
		public ResponseEntity<?> getUserByMailAndMatricule(
		        @PathVariable(value = "email") String email ,
		        @PathVariable (value = "matricule")String matricule) {
		    try {
		        System.out.println("Received request with mail: " + email + " and matricule: " + matricule);
		        User user = userService.getUserByMailAndMatricule(email, matricule);

		        if (user != null) {
		            return new ResponseEntity<>(user, HttpStatus.OK);
		        } else {
		            System.out.println("User not found");
		            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
		        }
		    } catch (Exception e) {
		        System.out.println("An error occurred: " + e.getMessage());
		        return new ResponseEntity<>("An error occurred: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
		    }
		}
	 
	  
	  
	 @GetMapping("/findbyMatricule/{matricule}")
		public ResponseEntity<?>findUserByMatricule( @PathVariable String matricule) {
		    try {
		        
		        User user = userService.findUserByMatricule(matricule);

		        if (user != null) {
		            return new ResponseEntity<>(user, HttpStatus.OK);
		        } else {
		            System.out.println("User not found");
		            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
		        }
		    } catch (Exception e) {
		        System.out.println("An error occurred: " + e.getMessage());
		        return new ResponseEntity<>("An error occurred:" + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
		    }
		}
	 
	 private String generateVerificationCode() {
		    Random random = new Random();
		    int code = 100000 + random.nextInt(900000);
		    return String.valueOf(code);
		}
		
		public void sendVerificationCodeByEmail(String to, String verificationCode) {
	        MimeMessage message = javaMailSender.createMimeMessage();
	        MimeMessageHelper helper = new MimeMessageHelper(message);

	        try {
	            helper.setTo(to);
	            helper.setSubject("Verification Code for Password Reset");
	            String emailContent = "Your verification code for password reset is: " + verificationCode;
	            helper.setText(emailContent);

	            javaMailSender.send(message);
	        } catch (MessagingException e) {
	            e.printStackTrace();
	        }
	    }
	 
	

	 
	
	 @PutMapping("/updatepw/{user_id}")
	 public ResponseEntity<ApiResponse> modifierMotDePasse(
	         @PathVariable Long user_id,
	         @RequestBody String newPassword,
	         Authentication authentication) {

	     try {
	         System.out.println("Authenticated user: " + authentication.getName());
	         System.out.println("Authorities: " + authentication.getAuthorities());

	         // Récupérer l'utilisateur depuis la base de données
	         User user = userService.findUserById(user_id);

	         if (user != null) {
	             // Validation du nouveau mot de passe
	             if (!isValidPassword(newPassword)) {
	                 return new ResponseEntity<>(new ApiResponse("Le nouveau mot de passe ne respecte pas les critères de sécurité"), HttpStatus.BAD_REQUEST);
	             }

	             // Crypter le mot de passe et le mettre à jour en base de données
	             String hashedPassword = bCryptPasswordEncoder.encode(newPassword);
	             user.setPassword(hashedPassword);
	             userService.saveUser(user);

	             return new ResponseEntity<>(new ApiResponse("Mot de passe modifié avec succès"), HttpStatus.OK);
	         } else {
	             return new ResponseEntity<>(new ApiResponse("Utilisateur non trouvé"), HttpStatus.NOT_FOUND);
	         }
	     } catch (Exception e) {
	         return new ResponseEntity<>(new ApiResponse("Une erreur interne s'est produite"), HttpStatus.INTERNAL_SERVER_ERROR);
	     }
	 }

	 private boolean isValidPassword(String password) {
		    if (password.length() < 8) {
		        return false;
		    }
		    return true;
		}



	


}
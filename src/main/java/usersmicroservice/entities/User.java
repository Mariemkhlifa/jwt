package usersmicroservice.entities;

import java.sql.Date;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinTable;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToOne;
import usersmicroservice.register.VerificationToken;
//import usersmicroservice.register.VerificationToken;

@Entity
public class User {
@Id
@GeneratedValue (strategy=GenerationType.IDENTITY)
private Long user_id;


@Column(unique=true)
private String username;
private String lastName;
private String email;
private String password;
private String sexe;
private String matricule;
private String tel;
private Date dateNaissance;


@JsonIgnore
@OneToOne(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
private VerificationToken verificationToken;





 @ManyToMany(cascade=CascadeType.ALL, fetch = FetchType.EAGER)
@JoinTable(name="user_role",joinColumns = @JoinColumn(name="user_id") ,
 inverseJoinColumns = @JoinColumn(name="role_id"))
private List<Role> roles;
 
 
public User() {
	super();
}


public User(Long user_id, String username, String lastName, String email, String password, String sexe,
		String matricule, String tel, Date dateNaissance, Boolean enabled, List<Role> roles) {
	super();
	this.user_id = user_id;
	this.username = username;
	this.lastName = lastName;
	this.email = email;
	this.password = password;
	this.sexe = sexe;
	
	this.matricule = matricule;
	this.tel = tel;
	this.dateNaissance = dateNaissance;
	this.roles = roles;
}


public Long getUser_id() {
	return user_id;
}


public void setUser_id(Long user_id) {
	this.user_id = user_id;
}


public String getUsername() {
	return username;
}


public void setUsername(String username) {
	this.username = username;
}


public String getLastName() {
	return lastName;
}


public void setLastName(String lastName) {
	this.lastName = lastName;
}


public String getEmail() {
	return email;
}


public void setEmail(String email) {
	this.email = email;
}


public String getPassword() {
	return password;
}


public void setPassword(String password) {
	this.password = password;
}




public String getSexe() {
	return sexe;
}


public void setSexe(String sexe) {
	this.sexe = sexe;
}


public String getMatricule() {
	return matricule;
}


public void setMatricule(String matricule) {
	this.matricule = matricule;
}


public String getTel() {
	return tel;
}


public void setTel(String tel) {
	this.tel = tel;
}


public Date getDateNaissance() {
	return dateNaissance;
}


public void setDateNaissance(Date dateNaissance) {
	this.dateNaissance = dateNaissance;
}





public List<Role> getRoles() {
	return roles;
}


public void setRoles(List<Role> roles) {
	this.roles = roles;
}







public VerificationToken getVerificationToken() {
	return verificationToken;
}


public void setVerificationToken(VerificationToken verificationToken) {
	this.verificationToken = verificationToken;
}
 
 
 
 








}
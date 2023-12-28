package usersmicroservice.register;

import java.sql.Date;

public class RegistrationRequest {
	private String username;
	private String lastName;
	private String email;
	private String password;
	private String sexe;
	private String matricule;
	private String tel;
	private Date dateNaissance;
	
	
	
	public RegistrationRequest(String username, String lastName, String email, String password, String sexe,
			String matricule, String tel, Date dateNaissance) {
		super();
		this.username = username;
		this.lastName = lastName;
		this.email = email;
		this.password = password;
		this.sexe = sexe;
		this.matricule = matricule;
		this.tel = tel;
		this.dateNaissance = dateNaissance;
	}
	
	public RegistrationRequest() {
		super();
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
	
	
	
	
	
	

}

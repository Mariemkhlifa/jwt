package usersmicroservice.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import usersmicroservice.entities.Role;


public interface RoleRepository extends JpaRepository<Role, Long> {
Role findByRole(String role);
}


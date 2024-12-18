package com.arllansantana.springbootjwtauth.repository;


import java.util.Optional;

import com.arllansantana.springbootjwtauth.models.ERole;
import com.arllansantana.springbootjwtauth.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
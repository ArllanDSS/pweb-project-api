package com.arllansantana.springbootjwtauth.repository;

import com.arllansantana.springbootjwtauth.models.Consulta;
import com.arllansantana.springbootjwtauth.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ConsultaRepository extends JpaRepository<Consulta, Long> {
    List<Consulta> findByUser(User user);

}
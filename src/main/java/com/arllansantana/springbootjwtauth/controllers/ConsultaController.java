package com.arllansantana.springbootjwtauth.controllers;

import com.arllansantana.springbootjwtauth.models.Consulta;
import com.arllansantana.springbootjwtauth.models.User;
import com.arllansantana.springbootjwtauth.payload.response.MessageResponse;
import com.arllansantana.springbootjwtauth.repository.ConsultaRepository;
import com.arllansantana.springbootjwtauth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/consultas")
public class ConsultaController {

    @Autowired
    private ConsultaRepository consultaRepository;

    @Autowired
    private UserRepository userRepository;

    @PostMapping
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> marcarConsulta(@RequestBody Consulta consulta) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String cpf = authentication.getName();

        User user = userRepository.findByCpf(cpf)
                .orElseThrow(() -> new RuntimeException("Error: User not found"));

        consulta.setUser(user);
        consultaRepository.save(consulta);

        return ResponseEntity.ok(consulta);
    }

    @GetMapping
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<?> obterConsultasDoUsuario() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String cpf = authentication.getName();

        User user = userRepository.findByCpf(cpf)
                .orElseThrow(() -> new RuntimeException("Error: User not found"));

        List<Consulta> consultas = consultaRepository.findByUser(user);
        return ResponseEntity.ok(consultas);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<?> cancelarConsulta(@PathVariable Long id) {
        try {
            consultaRepository.deleteById(id);
            return ResponseEntity.ok(new MessageResponse("Consulta cancelada com sucesso!"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse("Erro ao cancelar consulta."));
        }
    }
}
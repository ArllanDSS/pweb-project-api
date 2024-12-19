package com.arllansantana.springbootjwtauth.controllers;

import com.arllansantana.springbootjwtauth.models.ERole;
import com.arllansantana.springbootjwtauth.models.Role;
import com.arllansantana.springbootjwtauth.models.User;
import com.arllansantana.springbootjwtauth.payload.request.AtualizarSenhaDTO;
import com.arllansantana.springbootjwtauth.payload.request.AtualizarUsuarioDTO;
import com.arllansantana.springbootjwtauth.payload.request.LoginRequest;
import com.arllansantana.springbootjwtauth.payload.request.SignupRequest;
import com.arllansantana.springbootjwtauth.payload.response.JwtResponse;
import com.arllansantana.springbootjwtauth.payload.response.MessageResponse;
import com.arllansantana.springbootjwtauth.repository.RoleRepository;
import com.arllansantana.springbootjwtauth.repository.UserRepository;
import com.arllansantana.springbootjwtauth.security.jwt.JwtUtils;
import com.arllansantana.springbootjwtauth.security.services.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getCpf(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByCpf(signUpRequest.getCpf())) { // Validação do CPF
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: CPF is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User();
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(encoder.encode(signUpRequest.getPassword()));
        user.setNome(signUpRequest.getNome());
        user.setSobrenome(signUpRequest.getSobrenome());
        user.setDataNascimento(signUpRequest.getDataNascimento());
        user.setCpf(signUpRequest.getCpf());
        user.setSexo(signUpRequest.getSexo());

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PutMapping("/atualizar")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<?> atualizarUsuario(
            @Valid @RequestBody AtualizarUsuarioDTO atualizarUsuarioDTO,
            Authentication authentication
    ) {
        try {
            // Obtendo o token JWT
//            String token = authentication.getCredentials().toString().replace("Bearer ", "");
            String cpf = authentication.getName();
            User user = userRepository.findByCpf(cpf)
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

            System.out.println("Atualizando usuário com CPF: " + cpf);

            if (atualizarUsuarioDTO.getNome() != null) {
                user.setNome(atualizarUsuarioDTO.getNome());
                System.out.println("Nome atualizado para: " + atualizarUsuarioDTO.getNome());
            }
            if (atualizarUsuarioDTO.getSobrenome() != null) {
                user.setSobrenome(atualizarUsuarioDTO.getSobrenome());
                System.out.println("Sobrenome atualizado para: " + atualizarUsuarioDTO.getSobrenome());
            }
            if (atualizarUsuarioDTO.getEmail() != null) {
                user.setEmail(atualizarUsuarioDTO.getEmail());
                System.out.println("Email atualizado para: " + atualizarUsuarioDTO.getEmail());
            }
            if (atualizarUsuarioDTO.getDataNascimento() != null) {
                user.setDataNascimento(atualizarUsuarioDTO.getDataNascimento());
                System.out.println("Data de Nascimento atualizada para: " + atualizarUsuarioDTO.getDataNascimento());
            }
            if (atualizarUsuarioDTO.getCpf() != null) {
                user.setCpf(atualizarUsuarioDTO.getCpf());
                System.out.println("CPF atualizado para: " + atualizarUsuarioDTO.getCpf());
            }
            if (atualizarUsuarioDTO.getSexo() != null) {
                user.setSexo(atualizarUsuarioDTO.getSexo());
                System.out.println("Sexo atualizado para: " + atualizarUsuarioDTO.getSexo());
            }

            userRepository.save(user);
            System.out.println("Usuário atualizado com sucesso!");
            return ResponseEntity.ok(new MessageResponse("Usuário atualizado com sucesso!"));
        } catch (Exception e) {
            System.err.println("Erro ao atualizar usuário: " + e.getMessage());
            return ResponseEntity.badRequest().body(new MessageResponse("Erro ao atualizar usuário"));
        }
    }

    @PutMapping("/atualizar-senha")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<?> atualizarSenha(
            @Valid @RequestBody AtualizarSenhaDTO atualizarSenhaDTO,
            Authentication authentication
    ) {
        try {
            if (!atualizarSenhaDTO.getNovaSenha().equals(atualizarSenhaDTO.getConfirmarSenha())) {
                return ResponseEntity.badRequest().body(new MessageResponse("Senhas não coincidem!"));
            }

            String cpf = authentication.getName();
            User user = userRepository.findByCpf(cpf)
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

            user.setPassword(encoder.encode(atualizarSenhaDTO.getNovaSenha()));
            userRepository.save(user);

            return ResponseEntity.ok(new MessageResponse("Senha atualizada com sucesso!"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse("Erro ao atualizar senha"));
        }
    }

}
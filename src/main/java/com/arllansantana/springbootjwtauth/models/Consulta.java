package com.arllansantana.springbootjwtauth.models;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "consultas")
@Data
public class Consulta {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(cascade = CascadeType.PERSIST)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String unidade;

    @Column(nullable = false)
    private String especialidade;

    @Column(nullable = false)
    private String data;

    @Column(nullable = false)
    private String hora;

}
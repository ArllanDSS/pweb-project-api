package com.arllansantana.springbootjwtauth.payload.request;

import lombok.Data;

@Data
public class AtualizarUsuarioDTO {

    private String nome;
    private String sobrenome;
    private String email;
    private String dataNascimento;
    private String cpf;
    private String sexo;
}
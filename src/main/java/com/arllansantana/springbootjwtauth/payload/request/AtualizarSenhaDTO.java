package com.arllansantana.springbootjwtauth.payload.request;

import lombok.Data;

@Data
public class AtualizarSenhaDTO {

    private String novaSenha;
    private String confirmarSenha;

}

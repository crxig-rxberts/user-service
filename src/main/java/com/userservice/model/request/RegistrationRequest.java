package com.userservice.model.request;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class RegistrationRequest {

    @Size(min = 3, max = 16)
    private String userId;

    @Size(min = 2, max = 35)
    private String firstName;

    @Size(min = 2, max = 35)
    private String lastName;

    @NotNull
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$",
            message = "Password must contain at least 8 characters, including one lowercase letter, one uppercase letter, one number, and one special character")
    private String password;

    @Email
    private String email;
}

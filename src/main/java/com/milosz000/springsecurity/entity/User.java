package com.milosz000.springsecurity.entity;

import com.milosz000.springsecurity.entity.enums.Role;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/* lombok @Data annotation adds:
- Getters/Setters
- ToString
- EqualsAndHashCode
- RequiredArgsConstructor
methods
*/
@Data
// design pattern builder
@Builder
@NoArgsConstructor
// builder needs AllArgsConstructor
@AllArgsConstructor
@Entity
/* default name would be "User", but it is reserved keyword in PostgreSQL, so to avoid conflict, I changed name of table
to "_user" */
@Table(name = "_user")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // NotBlank annotation means: the string is not null and the trimmed length is greater than zero -> " " is not valid
    @NotBlank(message = "Please enter your name")
    private String firstName;

    @NotBlank(message = "Please enter your last name")
    private String lastName;

    @Email(message = "Invalid email. Please enter proper email")
    @NotBlank(message = "Please enter your email")
    private String email;

    /* generate column as a VARCHAR(60) and trying to insert a longer sting will result in an SQL error
    @Column is used only to specify table column properties, so it doesn't provide validations.
    Length is set to 60 because BCrypt algorithm generates a String o length 60 */
    @Column(length = 60)
    @NotBlank(message = "Please enter your password")
    private String password;

    // values are store as strings (ORDINAL = ints)
    @Enumerated(EnumType.STRING)
    private Role role;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        /* I will return only one object which is user role, but I have to use List.of() because method getAuthorities()
        returns Collection */
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

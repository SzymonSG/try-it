package com.example.demo.student.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static com.example.demo.student.security.ApplicationUserPermission.*;

public enum AplicationUserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ,COURSE_WRITE,STUDENT_READ,STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ,STUDENT_READ));

    // wstrzyknięcie odpowiednich danych do tej klasy i setów
    private final Set<ApplicationUserPermission> permissions;
    AplicationUserRole(Set<ApplicationUserPermission> permissions) {

        this.permissions = permissions;
    }
    //Getter dający dostęp do elementów Setów.
    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities(){

        //przerobienie
        //STUDENT_READ("student:read"),
        //        STUDENT_WRITE("student:write"),
        //        COURSE_READ("course:read"),
        //        COURSE_WRITE("course:write");
        // na SimpleGrantedAuthority i zkolektowanie ich do Setu
        Set<SimpleGrantedAuthority> permissionss = getPermissions().stream()
                .map(permissions -> new SimpleGrantedAuthority(permissions.getPermission()))// przekazanie Stringa jako role do konstruktora
                .collect(Collectors.toSet());
        // dodanie do każdego rodzaju permission nazwy ROLE_
        permissionss.add(new SimpleGrantedAuthority("ROLE_"+ this.name()));

        return permissionss;

    }
}


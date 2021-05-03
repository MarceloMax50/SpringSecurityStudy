package com.example.demo.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.example.demo.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(
            COURSE_READ,
            COURSE_WRITE,
            STUDENT_READ,
            STUDENT_WHITE
    )),
    ADMINTRAINEE(Sets.newHashSet(
            COURSE_READ,
            STUDENT_READ
    ));

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {

        this.permissions = permissions;
    }
    private final Set<ApplicationUserPermission> permissions;


}

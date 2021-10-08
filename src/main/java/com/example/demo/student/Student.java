package com.example.demo.student;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class Student {

    private final Integer srtudentId;
    private final String stdunetName;

    @Override
    public String toString() {
        return "Student{" +
                "srtudentId=" + srtudentId +
                ", stdunetName='" + stdunetName + '\'' +
                '}';
    }
}

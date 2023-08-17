package org.ms.usermanagementportal.service;


public interface EmailService {
    void sendNewPasswordEmail(String firstName, String password, String email);
}

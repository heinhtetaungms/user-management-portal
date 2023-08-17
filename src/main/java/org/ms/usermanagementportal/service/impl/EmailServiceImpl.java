package org.ms.usermanagementportal.service.impl;

import org.ms.usermanagementportal.service.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import static org.ms.usermanagementportal.constant.EmailConstant.EMAIL_SUBJECT;

@Service
public class EmailServiceImpl implements EmailService {

    @Autowired
    private JavaMailSender mailSender;
    @Value("${spring.mail.username}")
    private String sender;

    @Override
    public void sendNewPasswordEmail(String firstName, String password, String email) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(sender);
        message.setTo(email);
        message.setSubject(EMAIL_SUBJECT);
        message.setText(String.format("New Password was : %s", password));
        mailSender.send(message);
    }
}

package org.ms.usermanagementportal.constant;

public class SecurityConstant {
    public static final long EXPIRATION_TIME = 5*(60*60*24*1000);  //5 days expressed in milliseconds
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
    public static final String KN_LLC = "KN, LLC";
    public static final String KN_ADMINISTRATION = "User Management Portal";
    public static final String AUTHORITIES = "Authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to login to access this page";
    public static final String ACCESS_DENIED_MESSAGE = "You do not have permission to access this page";
    public static final String OPTIONS_HTTP_METHOD = "OPTIONS";
    public static final String [] PUBLIC_URLS = {"/user/login", "/user/register", "/user/resetPassword/**", "/user/image/**"};
 //   public static final String [] PUBLIC_URLS = { "**" };

}

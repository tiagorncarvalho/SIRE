package sire.configuration;

public class AppAdmin {
    private final String username;
    private final String password;

    public AppAdmin(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}

package com.test.authservice.security;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service //Nó phải được chú thích bằng @Service.
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private BCryptPasswordEncoder encoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // hard coding the users. All passwords must be encoded.
        final List<AppUser> users = Arrays.asList(
                new AppUser(1, "hung", encoder.encode("12345"), "USER"),
                new AppUser(2, "admin", encoder.encode("12345"), "ADMIN")
        );


        for(AppUser appUser: users) {
            if(appUser.getUsername().equals(username)) {

                // Hãy nhớ rằng Spring cần các vai trò ở định dạng này: "ROLE_" + userRole (tức là "ROLE_ADMIN")
                // Vì vậy, chúng tôi cần đặt nó thành định dạng đó, để chúng tôi có thể xác minh và so sánh các vai trò (tức là hasRole ("ADMIN")).
                List<GrantedAuthority> grantedAuthorities = AuthorityUtils
                        .commaSeparatedStringToAuthorityList("ROLE_" + appUser.getRole());

                // Lớp "Người dùng" được cung cấp bởi Spring và đại diện cho một lớp mô hình cho người dùng được UserDetailsService trả về
                // Và được sử dụng bởi trình quản lý auth để xác minh và kiểm tra xác thực người dùng.
                return new User(appUser.getUsername(), appUser.getPassword(), grantedAuthorities);
            }
        }

        // Nếu người dùng không được tìm thấy. Bỏ trường hợp ngoại lệ này.
        throw new UsernameNotFoundException("Username: " + username + " not found");
    }

    // Một lớp (tạm thời) đại diện cho người dùng được lưu trong cơ sở dữ liệu.
    private static class AppUser {
        private Integer id;
        private String username, password;
        private String role;

        public AppUser(Integer id, String username, String password, String role) {
            this.id = id;
            this.username = username;
            this.password = password;
            this.role = role;
        }

        public Integer getId() {
            return id;
        }

        public void setId(Integer id) {
            this.id = id;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }
    }
}

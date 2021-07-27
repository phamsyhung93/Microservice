package com.test.authservice.security;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity //Bật cấu hình bảo mật. Chú thích này biểu thị cấu hình cho bảo mật spring
public class SecurityCredentialsConfig extends WebSecurityConfigurerAdapter{
    @Autowired
    private UserDetailsService detailsService;

    @Autowired
    private JwtConfig jwtConfig;

    @Override
    protected void configure(HttpSecurity   http) throws Exception {
        http
                .csrf().disable()
                // đảm bảo rằng chúng tôi sử dụng phiên không trạng thái; phiên sẽ không được sử dụng để lưu trữ trạng thái của người dùng.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // xử lý các nỗ lực được ủy quyền
                .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                // Thêm bộ lọc để xác thực thông tin đăng nhập của người dùng và thêm mã thông báo vào tiêu đề phản hồi
                // Xác thựcManager () là gì?
                // Một đối tượng được cung cấp bởi WebSecurityConfigurerAdapter, được sử dụng để xác thực người dùng chuyển thông tin đăng nhập của người dùng
                // Bộ lọc cần trình quản lý xác thực này để xác thực người dùng.
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig))
                .authorizeRequests()
                // cho phép tất cả các yêu cầu POST
                .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
                // bất kỳ yêu cầu nào khác phải được xác thực
                .anyRequest().authenticated();
    }

    // Spring có giao diện UserDetailsService, có thể được ghi đè để cung cấp triển khai của chúng tôi để tìm nạp người dùng từ cơ sở dữ liệu (hoặc bất kỳ nguồn nào khác).
    // Đối tượng UserDetailsService được sử dụng bởi trình quản lý xác thực để tải người dùng từ cơ sở dữ liệu.
    // Ngoài ra, chúng ta cũng cần xác định bộ mã hóa mật khẩu. Vì vậy, người quản lý xác thực có thể so sánh và xác minh mật khẩu.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(detailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public JwtConfig jwtConfig() {
        return new JwtConfig();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

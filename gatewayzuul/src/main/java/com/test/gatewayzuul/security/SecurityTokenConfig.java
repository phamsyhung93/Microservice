package com.test.gatewayzuul.security;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private JwtConfig jwtConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                // đảm bảo rằng chúng ta sử dụng phiên không trạng thái; phiên sẽ không được sử dụng để lưu trữ trạng thái của người dùng.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // xử lý các nỗ lực được ủy quyền
                .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                // Thêm bộ lọc để xác thực mã thông báo với mọi yêu cầu
                .addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
                // cấu hình yêu cầu ủy quyền
                .authorizeRequests()
                // cho phép tất cả những ai đang truy cập dịch vụ "auth"
                .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
                // phải là quản trị viên nếu cố gắng truy cập khu vực quản trị (xác thực cũng được yêu cầu ở đây)
                .antMatchers("/gallery" + "/admin/**").hasRole("ADMIN")
                // Mọi yêu cầu khác phải được xác thực
                .anyRequest().authenticated();
    }

    @Bean
    public JwtConfig jwtConfig() {
        return new JwtConfig();
    }
}

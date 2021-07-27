package com.test.gatewayzuul.security;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JwtTokenAuthenticationFilter extends OncePerRequestFilter  {

    private final JwtConfig jwtConfig;

    public JwtTokenAuthenticationFilter(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // 1. lấy tiêu đề xác thực. Các mã thông báo phải được chuyển trong tiêu đề xác thực
        String header = request.getHeader(jwtConfig.getHeader());

        // 2. xác thực tiêu đề và kiểm tra tiền tố
        if(header == null || !header.startsWith(jwtConfig.getPrefix())) {
            chain.doFilter(request, response);        // If not valid, go to the next filter.
            return;
        }

        // Nếu không có mã thông báo nào được cung cấp và do đó người dùng sẽ không được xác thực.
        // Ổn mà. Có thể người dùng đang truy cập đường dẫn công khai hoặc yêu cầu mã thông báo.
        // Tất cả các đường dẫn bảo mật cần mã thông báo đã được xác định và bảo mật trong lớp cấu hình.
        // Và Nếu người dùng cố gắng truy cập mà không có mã thông báo truy cập, thì anh ta sẽ không được xác thực và một ngoại lệ sẽ được ném ra.
        // 3.Lấy mã thông báo
        String token = header.replace(jwtConfig.getPrefix(), "");

        try {
            // các ngoại lệ có thể được đưa ra khi tạo các xác nhận quyền sở hữu nếu ví dụ: mã thông báo đã hết hạn
            // 4. Xác thực mã thông báo
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtConfig.getSecret().getBytes())
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();
            if(username != null) {
                @SuppressWarnings("unchecked")
                List<String> authorities = (List<String>) claims.get("authorities");

                // 5. Tạo đối tượng xác thực
                // UsernamePasswordAuthenticationToken: Một đối tượng tích hợp, được sử dụng bởi spring để đại diện cho người dùng được xác thực / đang được xác thực hiện tại.
                // Nó cần một danh sách các cơ quan có thẩm quyền, có loại giao diện GrantedAuthority, trong đó SimpleGrantedAuthority là một triển khai của giao diện đó
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                username, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

                // 6. Xác thực người dùng
                // Bây giờ, người dùng đã được xác thực
                SecurityContextHolder.getContext().setAuthentication(auth);
            }

        } catch (Exception e) {
            // Trong trường hợp không thành công. Đảm bảo rằng nó rõ ràng; vì vậy đảm bảo người dùng sẽ không được xác thực
            SecurityContextHolder.clearContext();
        }

        // chuyển đến bộ lọc tiếp theo trong chuỗi bộ lọc
        chain.doFilter(request, response);
    }

}

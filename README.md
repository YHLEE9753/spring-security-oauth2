# Spring security OAuth2 + JWT
# 1. OAuth2 + JWT 구현
## 1. init: project setting
java : 17<br>
gradle<br>
spring boot version : 2.6.9
```groovy
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-validation'
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'javax.xml.bind:jaxb-api'
    implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
    implementation 'jakarta.xml.bind:jakarta.xml.bind-api:4.0.0'

    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
    compileOnly 'org.projectlombok:lombok'
    developmentOnly 'org.springframework.boot:spring-boot-devtools'
    runtimeOnly 'mysql:mysql-connector-java'
    annotationProcessor 'org.projectlombok:lombok'

    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testImplementation 'org.springframework.security:spring-security-test'
}
```

## 2. 초기 security 설정
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable(); // rest api -> http 로그인 페이지 폼 X
        http.csrf().disable(); // rest api -> csrf 보안 X
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests()
            .anyRequest().authenticated(); // 인증 필쵸
    }
}
```

## 3. appication.yaml 설정
- 구글, 네이버의 인증서버 정보를 추가한다.
- redirect uri 를 추가한다.

## 4. OAuth2 인증이 완료된 후 받은 데이터로 우리의 서비스에 접근할 수 있도록 인증 정보를 생성해주는 서비스 작성
- OAuth2UserService 인터페이스를 구현한 CustomOAuth2UserService 를 만든다.
- OAuth2 인증 후 보내는 데이터가 각 인증 서버마다 다르므로 별도의 분기 처리가 이루어 진다.
- 최종적으로 인증서버에서 받은 데이터를 가진 User 객체를 권한부여와 함께 반환하게 된다.
```java
@Slf4j
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        DefaultOAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
            .getUserInfoEndpoint().getUserNameAttributeName();

        // 각 인증 서버에 맞게 OAuth Attribute 를 생성한다.
        OAuth2Attribute oAuth2Attribute = OAuth2Attribute.of(registrationId, userNameAttributeName,
            oAuth2User.getAttributes());

        log.info("{}", oAuth2Attribute);

        // 생성된 Attribute 를 Map 으로 convert 한다.
        Map<String, Object> memberAttribute = oAuth2Attribute.convertToMap();

        // 생성된 OAuth 유저에 User 권한을 부여한 후 반환한다.
        return new DefaultOAuth2User(
            Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
            memberAttribute, "email"
        );
    }
}
```

## 5. 토큰 발급 후 검증
- 토큰은 API서버에 접근하기 위한 AccessToken 과 인증 토큰이 만료되었을 경우 리프레쉬에 사용할 RefreshToken 으로 이루어져 있습니다.
- AccessToken, RefreshToken 를 Token 에 담아 생성한다.
- AccessToken 의 만료시간은 10분, RefreshToken 의 만료시간은 3주로 하였습니다.
```java
@ToString
@NoArgsConstructor
@Getter
public class Token {
    private String token;
    private String refreshToken;

    public Token(String token, String refreshToken) {
        this.token = token;
        this.refreshToken = refreshToken;
    }
}

@Service
public class TokenService {
    // 추가 리펙토링 필요
    private String secretKey = "token-secret-key-double-caseqwdqwdqwdqwdqwdqwdwqdqwdq";

    @PostConstruct // 의존성 주입 후 초기화(Key 생성)
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // 토큰 생성
    public Token generateToken(String uid, String role) {
        // AccessToken 만료기간 : 10분
        long tokenPeriod = 1000L * 60L * 10L;
        // RefreshToken 만료기간 : 3주
        long refreshPeriod = 1000L * 60L * 60L * 24L * 30L * 3L;

        // Claims 에 권한 설정(uid : email(식별자))
        Claims claims = Jwts.claims().setSubject(uid);
        claims.put("role", role);

        Date now = new Date();
        // AccessToken, RefreshToken 를 Token 에 담아 반환한다.
        return new Token(
            Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + tokenPeriod))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact(),
            Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + refreshPeriod))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact());
    }

    public boolean verifyToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token);
            return claims.getBody()
                .getExpiration()
                .after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public String getUid(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }
}
```

## 6. OAuth2 로그인 성공시 핸들러에서 토큰을 생성 후 response header에 추가해서 보내준다.
- 핸들러에서 유저 서비스를 이용하여 회원가입 및 로그인 처리가 가능하다
- failure handler 를 통해 추가로 로그인 연속 실패 시 로직도 추가할 수 있다.
```java
@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final TokenService tokenService;
    private final UserRequestMapper userRequestMapper;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
        throws IOException, ServletException {
        // 인증 된 principal 를 가지고 온다.
        OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
        UserDto userDto = userRequestMapper.toDto(oAuth2User);

        // (추후 리팩토링) 최초 로그인이라면 회원가입 처리를 한다.

        // 토큰 생성
        Token token = tokenService.generateToken(userDto.getEmail(), "USER");
        log.info("{}", token);

        writeTokenResponse(response, token);
    }

    private void writeTokenResponse(HttpServletResponse response, Token token)
        throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        response.addHeader("Auth", token.getToken());
        response.addHeader("Refresh", token.getRefreshToken());
        response.setContentType("application/json;charset=UTF-8");

        var writer = response.getWriter();
        writer.println(objectMapper.writeValueAsString(token));
        writer.flush();
    }
}
```

## 7. Security 설정에 OAuth2 로그인을 활성화하고 앞서 만든 서비스와 인증이 성공하면 처리할 Handler를 등록합니다.
```java
@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CustomOAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler successHandler;
    private final TokenService tokenService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable(); // rest api -> http 로그인 페이지 폼 X
        http.csrf().disable(); // rest api -> csrf 보안 X
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests()
            .anyRequest().authenticated(); // 인증 필요
        http.oauth2Login().successHandler(successHandler).userInfoEndpoint().userService(oAuth2UserService);

    }
}

```

## 8. 프로젝트 실행 후 /oauth2/authorization/naver 로 접근하면 네이버 로그인을 시도하고, 인증이 되면 토큰을 발급해주는 것을 확인할 수 있습니다.

## 9. 발급받은 토큰을 이용하여 Security 인증을 처리하는 필터를 만들어 준다.
- API 서버에 접근할 떄 Auth 헤더에 발급받은 토큰을 함께 보내면 토큰값에서 유저정보를 가져와 회원가입이 되었는지 검증 후 인증을 할 수 있다.
- 토큰이 존재하는지, 유효한지, 유효기간이 지났는지 검증한다.
```java

@RequiredArgsConstructor
public class JwtAuthFilter extends GenericFilterBean {
    private final TokenService tokenService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException, ServletException {
        String token = ((HttpServletRequest)request).getHeader("Auth");

        // 토큰이 있는지, 유효한지 검증
        if (token != null && tokenService.verifyToken(token)) {
            String email = tokenService.getUid(token);

            // DB연동을 안했으니 이메일 정보로 유저를 만들어주겠습니다
            UserDto userDto = UserDto.builder()
                .email(email)
                .name("이름")
                .picture("프로필 이미지").build();

            Authentication auth = getAuthentication(userDto);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(request, response);
    }

    // UsernamePasswordAuthenticationToken 생성
    public Authentication getAuthentication(UserDto member) {
        return new UsernamePasswordAuthenticationToken(member, "",
            Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
    }
}
```

## 10. UsernamePasswordAuthenticationFilter필터 앞에 만든 JwtAuthFilter를 등록합니다.
- 추가로 토큰이 만료되어 인증을 하지 못하면 /token/expired로 리다이렉트하여 Refresh요청을 해야한다는 것을 알려주고 Refresh를 할 수 있도록 /token/** 을 전체 허용해줍니다.
```java
@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CustomOAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler successHandler;
    private final TokenService tokenService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable(); // rest api -> http 로그인 페이지 폼 X
        http.csrf().disable(); // rest api -> csrf 보안 X
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests()
            .antMatchers("/token/**").permitAll()
            .anyRequest().authenticated(); // 인증 필요
        http.oauth2Login().successHandler(successHandler).userInfoEndpoint().userService(oAuth2UserService);

        http.addFilterBefore(new JwtAuthFilter(tokenService), UsernamePasswordAuthenticationFilter.class);

    }
}
```
+ 토큰이 만료되었을 경우 Refresh 요청을 하기 위한 endpoint를 만들어준다.
```java
@RequiredArgsConstructor
@RestController
public class TokenController {
    private final TokenService tokenService;

    @GetMapping("/token/expired")
    public String auth() {
        throw new RuntimeException();
    }

    @GetMapping("/token/refresh")
    public String refreshAuth(HttpServletRequest request, HttpServletResponse response) {
        String token = request.getHeader("Refresh");

        if (token != null && tokenService.verifyToken(token)) {
            String email = tokenService.getUid(token);
            Token newToken = tokenService.generateToken(email, "USER");

            response.addHeader("Auth", newToken.getToken());
            response.addHeader("Refresh", newToken.getRefreshToken());
            response.setContentType("application/json;charset=UTF-8");

            return "HAPPY NEW TOKEN";
        }

        throw new RuntimeException();
    }
}
```

# 2. JPA 연동 및 리팩토링
# Spring security OAuth2 + JWT + redis
- Spring security OAuth2 를 이용하여 회원가입, 로그인, 로그아웃, 인증, 인가 구현
- Accesstoken Refrestoken 을 이용한 JWT 활용
- redis 를 이용한 로그아웃 구현
- redis 를 이용한 OAuth2 이후 추가 로그인 정보 기입후 회원가입 구현
- redis 와 blackList 기법을 적용한 logout 구현

---
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
    implementation 'com.github.ulisesbocchio:jasypt-spring-boot-starter:3.0.4'

    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
    compileOnly 'org.projectlombok:lombok'
    developmentOnly 'org.springframework.boot:spring-boot-devtools'
    runtimeOnly 'mysql:mysql-connector-java'
    annotationProcessor 'org.projectlombok:lombok'
    annotationProcessor "org.springframework.boot:spring-boot-configuration-processor"

    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testImplementation 'org.springframework.security:spring-security-test'
}
```

## 2. 도메인 작성(User, Role) 및 repository 생성
- 식별자로 username 에 Email 을 같는다.(AuthUser - Subject)
- 회원가입 시 기본적으로 ROLE_USER 을 가지게 된다.
- JPARepository 를 이용하여 UserRepo 를 생성한다.
```java
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String name;
    private String username; // john123 or email 도 String 이므로 가능하다
    private String picture;
    @Enumerated(EnumType.STRING)
    private Role role;
```
## 3. OAuth2 설정
- 네이버 developer, 구글 API 에 어플리케이션을 등록합니다.
- 등록 후 client-id, client-secret, redirect-uri 를 application.yaml 에 작성합니다.

## 4. OAuth2 인증이 완료된 후 받은 데이터로 우리의 서비스에 접근할 수 있도록 인증 정보를 생성해주는 서비스 작성
- OAuth2UserService 인터페이스를 구현한 CustomOAuth2UserService 를 만든다.
- OAuth2 인증 후 보내는 데이터가 각 인증 서버마다 다르므로 별도의 분기 처리가 이루어 진다.
- 최종적으로 인증서버에서 받은 데이터를 가진 User 객체를 권한부여와 함께 반환하게 된다.
- DB 저장 및 조회 로직을 작성한다.
```java
@Slf4j
@Service
@Primary
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User>,
    UserService {
    private final UserRepo userRepo;

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

        // 생성된 Attribute 를 Map 으로 convert 한다.
        Map<String, Object> memberAttribute = oAuth2Attribute.convertToMap();

        // 생성된 OAuth 유저에 User 권한을 부여한 후 반환한다.
        return new DefaultOAuth2User(
            Collections.singleton(new SimpleGrantedAuthority(ROLE_USER.stringValue)),
            memberAttribute, "email"
        );
    }

    @Override
    @Transactional
    public User saveUser(User member) {
        log.info("Saving new member {} to the database", member.getName());
        return userRepo.save(member);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> getUser(String username) {
        log.info("Fetching member {}", username);
        return userRepo.findByUsername(username);
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> getUsers() {
        log.info("Fetching all users");
        return userRepo.findAll();
    }
}

```
## 5. 토큰 발급 후 검증
- 토큰은 API서버에 접근하기 위한 AccessToken 과 인증 토큰이 만료되었을 경우 리프레쉬에 사용할 RefreshToken 으로 이루어져 있습니다.
- 토큰이 유효한지 검사하는 로직을 작성한다.
- AccessToken, RefreshToken 를 Token 에 담아 생성한다.
- Token 의 사용되는 secretkey 와 AccessToken, RefreshToken 의 만료시간은 yaml 파일을 통해 받아온다.

```java
@ToString
@NoArgsConstructor
@Getter
public class Token {
    private String accessToken;
    private String refreshToken;

    public Token(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}

@Service
@Slf4j
public class TokenService {
    private final JwtYamlRead jwtYamlRead;
    private String secretKey;
    private final long tokenPeriod;
    private final long refreshPeriod;

    public TokenService(JwtYamlRead jwtYamlRead) {
        this.jwtYamlRead = jwtYamlRead;
        this.secretKey = jwtYamlRead.getTokenSecret();
        this.tokenPeriod = jwtYamlRead.getTokenExpiry();
        this.refreshPeriod = jwtYamlRead.getRefreshTokenExpiry();
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // 토큰 생성
    public Token generateToken(String uid, String role) {

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

    public boolean verifyToken(String tokens) {
        try {
            Jws<Claims> claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(tokens);

            return claims.getBody()
                .getExpiration()
                .after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public String [] getRole(String tokens) {
        return new String [] {
            (String) Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(tokens)
                .getBody()
                .get("role")
        };
    }

    public String getUid(String tokens) {
        return Jwts.parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(tokens)
            .getBody()
            .getSubject();
    }

    public String changeToToken(String header) {
        return header.substring("Bearer ".length());
    }

    public long getRefreshPeriod() {
        return refreshPeriod;
    }
}

```
## 6. OAuth2 로그인 성공시 핸들러에서 토큰을 생성 후 response header에 추가해서 보내준다.
- 핸들러에서 유저 서비스를 이용하여 회원가입 및 로그인 처리가 가능하다
- failure handler 를 통해 추가로 로그인 연속 실패 시 로직도 추가할 수 있다.
- Authentication 에 성공한 경우 tokens 을 발행한다.
- AccessToken 은 body 에 담아서 전달하고, RefreshToken 은 http only Cookie 에 담아서 전달한다.
    - [LocalStorage vs. Cookies: JWT 토큰을 안전하게 저장하기 위해 알아야할 모든것](https://hshine1226.medium.com/localstorage-vs-cookies-jwt-%ED%86%A0%ED%81%B0%EC%9D%84-%EC%95%88%EC%A0%84%ED%95%98%EA%B2%8C-%EC%A0%80%EC%9E%A5%ED%95%98%EA%B8%B0-%EC%9C%84%ED%95%B4-%EC%95%8C%EC%95%84%EC%95%BC%ED%95%A0-%EB%AA%A8%EB%93%A0%EA%B2%83-4fb7fb41327c)

```java
@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final TokenService tokenService;
    private final ObjectMapper objectMapper;
    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication)
        throws IOException, ServletException {
        // 인증 된 principal 를 가지고 온다.
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String picture = (String) attributes.get("picture");

        // 최초 로그인이라면 회원가입 처리를 한다.(User 로 회원가입)
        userService.getUser(email)
            .orElseGet(() -> userService.saveUser(
                User.builder()
                    .username(email)
                    .name(name)
                    .picture(picture)
                    .role(ROLE_USER)
                    .build()
            ));

        // 토큰 생성
        Token tokens = tokenService.generateToken(email, ROLE_USER.stringValue);

        writeTokenResponse(response, tokens);
    }

    private void writeTokenResponse(HttpServletResponse response, Token tokens)
        throws IOException {
        response.setContentType("text/html;charset=UTF-8");
//        response.addHeader(AUTHORIZATION, "Bearer " + tokens.getAccessToken());
        response.setContentType("application/json;charset=UTF-8");

        // refresh tokens 은 cookie 로 전달한다.
        Cookie cookie = new Cookie("refreshToken",tokens.getRefreshToken());

        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) tokenService.getRefreshPeriod());

        response.addCookie(cookie);

        PrintWriter writer = response.getWriter();
        writer.println(objectMapper.writeValueAsString(tokens.getAccessToken()));
        writer.flush();
    }
}
```
## 7. 발급받은 토큰을 이용하여 Security 인증을 처리하는 필터를 만들어 준다.
- API 서버에 접근할 떄 Auth 헤더에 발급받은 토큰을 함께 보내면 토큰값에서 유저정보를 가져와 회원가입이 되었는지 검증 후 인증을 할 수 있다.
- 토큰이 존재하는지, 유효한지, 유효기간이 지났는지 검증한다.
```java
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {
    private final TokenService tokenService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException, ServletException {
        Optional<String> tokenHeader = Optional.ofNullable(((HttpServletRequest)request).getHeader(AUTHORIZATION));
        String tokens = tokenHeader.isPresent() ? tokenService.changeToToken(tokenHeader.get()) : null;

        // 토큰이 있는지, 유효한지 검증
        if (tokens != null && tokenService.verifyToken(tokens)) {
            // 토큰에서 username 과 role 를 가져온다.
            String username = tokenService.getUid(tokens);
            String[] roles = tokenService.getRole(tokens);

            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            Arrays.stream(roles).forEach(role -> {
                authorities.add(new SimpleGrantedAuthority(role));
            });
            UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
            // SecurityContextHolder에 설정한다. - 이곳을 통해 thread 당 해당 유저의 정보를 확인
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        }
        // 토큰이 유효하지 않은경우 다음 필터로 이동한다.
        chain.doFilter(request, response);
    }
}
```

## 8. SecurityConfig 설정에 필터와 핸들러를 추가한다.
- oauth2 로그인 성공지 OAuth2SuccessHandler 를 호출한다.
- UsernamePasswordAuthenticationFilter필터 앞에 만든 JwtAuthFilter를 등록한다.
- 토큰이 만료되어 인증을 하지 못하면 /tokens/expired로 리다이렉트하여 Refresh요청을 해야한다는 것을 알려주고 Refresh를 할 수 있도록 /tokens/** 을 전체 허용한다.
```java
@Configuration
@EnableWebSecurity
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

        // 순서 1
        // 로그인은 누구나 접근 가능하게 + 토큰 갱신
        http.authorizeRequests().antMatchers("/tokens/**","/login/**").permitAll();

        // 순서 2
        http.authorizeRequests().antMatchers(GET, "/api/member/**").hasAnyAuthority(ROLE_USER.stringValue);

        // 순서 3
        http.authorizeRequests().anyRequest().authenticated(); // 인증 필요

        http.logout().logoutSuccessUrl("/login");
        http.oauth2Login().successHandler(successHandler).userInfoEndpoint().userService(oAuth2UserService);
        http.addFilterBefore(new JwtAuthenticationFilter(tokenService), UsernamePasswordAuthenticationFilter.class);
    }
}
```

## 9. AccessToken이 만료되었을 경우 Refresh 요청을 하기 위한 endpoint를 만들어준다.
```java
@RequiredArgsConstructor
@RestController
@RequestMapping("/tokens")
public class TokenController {
    private final TokenService tokenService;

    @PostMapping("/refresh")
    public String refreshAuth(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = request.getHeader("Refresh");

        if (refreshToken != null && tokenService.verifyToken(refreshToken)) {
            String email = tokenService.getUid(refreshToken);
            Token newTokens = tokenService.generateToken(email, ROLE_USER.stringValue);

            response.addHeader(AUTHORIZATION, newTokens.getAccessToken());
            response.addHeader("Refresh", newTokens.getRefreshToken());
            response.setContentType("application/json;charset=UTF-8");

            return "HAPPY NEW TOKEN";
        }

        throw new RuntimeException();
    }
}
```

# 2. Refactoring
## 1. jjwt depreciated
- 일부 depreciated 된 로직이 존재한다.
- 코드 수정시 tokens 에서 verify 오류가 발생하여 수정하지 않고 있다.
- 추후 수정예정

## 2. submodule 을 통한 보안정보 격리
- submodule 을 통해 보안 정보를 격리시킨다
- 추후 수정예정

## 3. profile 적용
- 추후 수정예정

## 4. Jasypt 를 이용한 키 암호화
- 추후 수정예정


# Spring Security OPA Demo

## 使用Keycloak作为认证中心
如下命令启动Keycloak：
```
docker run  -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:18.0.0 start-dev
```
使用admin账号登陆到http://localhost:8080, 然后创建client 1008cache和user haitao，并为client 1008cache创建client角色app-user和app-admin，创建realm角色user，使之成为复合角色，并绑定到client 1008cache的app-user角色。然后分配角色user给user haitao。

具体如何使用Keycloak可参考[这里](https://medium.com/devops-dudes/securing-spring-boot-rest-apis-with-keycloak-1d760b2004e)。

## 获取JWT token
如下命令获取user haitao的JWT token。

```
curl -v -X POST http://10.200.10.1:8080/realms/master/protocol/openid-connect/token \
 --header 'Content-Type: application/x-www-form-urlencoded' \
 --data-urlencode 'grant_type=password' \
 --data-urlencode 'client_id=1008cache' \
 --data-urlencode 'client_secret=6VhM8Tg5GuzSV51VXPY2oiK1zToOlgCC' \
 --data-urlencode 'username=haitao' \
 --data-urlencode 'password=haitao'
 
 [output] {"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJWMXB5eUxObjBOYmkyOW9odzU5aFc1Y3JYdDg2TF9hRUIyaFFKeDRYVEFVIn0.eyJleHAiOjE2NTUzOTQyMjQsImlhdCI6MTY1NTM1ODIyNCwianRpIjoiOWJkZTk1ZTgtZDAxMS00YWY0LTlmMzctYTczY2Y0OTRlNjQ4IiwiaXNzIjoiaHR0cDovLzEwLjIwMC4xMC4xOjgwODAvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI4MzhhMDM5YS03MzMzLTRmZmMtYWNlMC00NWNlNjUyZTg3ODYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiIxMDA4Y2FjaGUiLCJzZXNzaW9uX3N0YXRlIjoiZGVjM2FjN2UtNjg0Ny00NzI0LTgzYzktYTlkZjBiYjM3NmQzIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJ1c2VyIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiMTAwOGNhY2hlIjp7InJvbGVzIjpbImFwcC11c2VyIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiJkZWMzYWM3ZS02ODQ3LTQ3MjQtODNjOS1hOWRmMGJiMzc2ZDMiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6ImhhaXRhbyJ9.Ose6Q1TI4iljjfMv6OE6EgDupsdyMOo75-x_ctekN7IvchRH3w8BZGYBsO17c1Nz6TV2e1ZaJExEjDzjrd74hb3v2Nycc2ehvobmwhvgerjAaBZ_teMhtkZZmR3lNvibzG8gdnt3wrxZ9E9WH49uAJH-rbD1PMtG0ocO-V1Gukre5Ml6wC2APh2KdXVcm9m2cKBto6HhSQAeXj11cAFd-85Ln4oUykDWHkUX4l1jBXtvchVdbLwF_QbyObjLEoP4h2xyisedlwBWf98MJnsAo2GI1Y7k8-xpnN_C9BB6SUc3acH_BCk3JQ-IjGtn8gVNzeKlyr8_B8mdlk4ss4S1Cg","expires_in":36000,"refresh_expires_in":1800,"refresh_token":"eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJiNzQyNDhhMS0xZjc0LTRmZTEtODA5YS1iM2EyYWE0YTY4NmEifQ.eyJleHAiOjE2NTUzNjAwMjQsImlhdCI6MTY1NTM1ODIyNCwianRpIjoiYjA2OTg3NjUtZWM2ZS00YjI2LWFiZjAtNmVjMmE0OTkwYTZlIiwiaXNzIjoiaHR0cDovLzEwLjIwMC4xMC4xOjgwODAvcmVhbG1zL21hc3RlciIsImF1ZCI6Imh0dHA6Ly8xMC4yMDAuMTAuMTo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJzdWIiOiI4MzhhMDM5YS03MzMzLTRmZmMtYWNlMC00NWNlNjUyZTg3ODYiLCJ0eXAiOiJSZWZyZXNoIiwiYXpwIjoiMTAwOGNhY2hlIiwic2Vzc2lvbl9zdGF0ZSI6ImRlYzNhYzdlLTY4NDctNDcyNC04M2M5LWE5ZGYwYmIzNzZkMyIsInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6ImRlYzNhYzdlLTY4NDctNDcyNC04M2M5LWE5ZGYwYmIzNzZkMyJ9.NodqmCm2WZoT1kCdhwmvWUu2LviFsclXGZnGGjIlvEg","token_type":"Bearer","not-before-policy":0,"session_state":"dec3ac7e-6847-4724-83c9-a9df0bb376d3","scope":"profile email"}%
```

通过jwt.io查看到如下payload信息：

```
{
  "exp": 1655394224,
  "iat": 1655358224,
  "jti": "9bde95e8-d011-4af4-9f37-a73cf494e648",
  "iss": "http://10.200.10.1:8080/realms/master",
  "aud": "account",
  "sub": "838a039a-7333-4ffc-ace0-45ce652e8786",
  "typ": "Bearer",
  "azp": "1008cache",
  "session_state": "dec3ac7e-6847-4724-83c9-a9df0bb376d3",
  "acr": "1",
  "realm_access": {
    "roles": [
      "default-roles-master",
      "offline_access",
      "uma_authorization",
      "user"
    ]
  },
  "resource_access": {
    "1008cache": {
      "roles": [
        "app-user"
      ]
    },
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "profile email",
  "sid": "dec3ac7e-6847-4724-83c9-a9df0bb376d3",
  "email_verified": false,
  "preferred_username": "haitao"
}
```
这段信息显示：user haitao拥有realm角色user，可以访问cleint 1008cache的app-user角色的资源。

## 定义Policy并测试
工程/policy目录下policy.rego文件，完成下面三件事：

1. 通过访问Keycloak的JWKS端点，验证JWT token，这个步骤可以忽略，因为身份验证已经由Spring Security SDK协助完成。此步骤仅用于说明身份认证和授权管理都可以由OPA完成。
2. 检查token中role角色中，如果拥有app-admin角色，则返回true，即允许访问所有路径，否则返回false
3. 检查token中role角色中，如果拥有app-user角色，且访问路径/user，则返回true，即允许访问，否则返回false

工程/policy目录下policy_test.rego文件，执行下面命令用于policy的单元测试：

```
# 工程/policy目录下
opa test . -v 
```

待Polocy测试完成后，如下命令启动OPA：

```
opa -w -s run -l debug .
```

使用如下curl命令测试，注意这里header.txt用于存放header内容，body.json用于存放bidy内容。

```
curl -v --location --request POST 'http://localhost:8181/v1/data/envoy/authz' --header @header.txt -d  @body.json | jq
```

## Spring Security OPA Demo

Spring Security OPA Demo使用Spring Security SDK进行身份验证，然后调用OPA进行授权裁决。


```
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Autowired
    ObjectMapper mapper;
    public AuthorizationManager<RequestAuthorizationContext> authorizationManager() {
        return (auth, context) -> {
            HttpResponse<String> response = callOPA(auth, context);
            return decideDecision(response);
        };
    }

    /**
     * https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html
     *
     * @param http
     * @return
     * @throws AuthenticationException
     */
    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().access(authorizationManager()))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt());
        return http.build();
    }

    Body buildBody(RequestAuthorizationContext context) {
        Body body = new Body();
        Input input = new Input();
        body.setInput(input);

        Attribute attributes = new Attribute();
        input.setAttributes(attributes);

        Request request = new Request();
        attributes.setRequest(request);

        HttpServletRequest httpRequest = context.getRequest();
        String token = httpRequest.getHeader("authorization");

        Http http = new Http(httpRequest.getMethod(), httpRequest.getRequestURI(), new Header(token));
        request.setHttp(http);

        System.out.println(httpRequest.getMethod() + ", " + httpRequest.getRequestURI() + ", " + token);
        return body;
    }

    AuthorizationDecision decideDecision(HttpResponse<String> Response) {
        if (Response.statusCode() != 200) {
            return new AuthorizationDecision(false);
        }

        try {
            Response response = mapper.readValue(Response.body(), Response.class);
            return new AuthorizationDecision(response.getResult().isAllow());
        } catch (JsonProcessingException je) {
            throw new RuntimeException(je);
        }
    }

    HttpResponse<String> callOPA(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
        var client = HttpClient.newBuilder().build();

        try {
            var request = HttpRequest.newBuilder()
                    .uri(new URI("http://localhost:8181/v1/data/envoy/authz"))
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(buildBody(context))))
                    .build();

            return client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

```

注意由Spring Security完成身份认证，需要配置Keycloak的jwk-set-uri或issuer-uri。

```
spring:
  application:
    name: opa-sec-demo
  security:
    oauth2:
      resourceserver:
        jwt:
#          issuer-uri: http://localhost:8080/realms/master
          jwk-set-uri: http://localhost:8080/realms/master/protocol/openid-connect/certs

```

## 验证Demo逻辑

执行如下命令验证：

```

export ACCESS_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJWMXB5eUxObjBOYmkyOW9odzU5aFc1Y3JYdDg2TF9hRUIyaFFKeDRYVEFVIn0.eyJleHAiOjE2NTU1ODE4OTIsImlhdCI6MTY1NTU0NTg5MiwianRpIjoiMGE2MWVlZTAtNDRhNy00Y2EzLTliYjQtZDA3Mjc1ZDM0YzE0IiwiaXNzIjoiaHR0cDovLzEwLjIwMC4xMC4xOjgwODAvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI4MzhhMDM5YS03MzMzLTRmZmMtYWNlMC00NWNlNjUyZTg3ODYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiIxMDA4Y2FjaGUiLCJzZXNzaW9uX3N0YXRlIjoiYzI3ZTJiYTUtZDc2My00YWU2LWE3MzUtYmFhZjQwZWIzNWYxIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJ1c2VyIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiMTAwOGNhY2hlIjp7InJvbGVzIjpbImFwcC11c2VyIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiJjMjdlMmJhNS1kNzYzLTRhZTYtYTczNS1iYWFmNDBlYjM1ZjEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6ImhhaXRhbyJ9.g1CgxB-h0dy-agG08kmar_SsFlghwtnWLeoVXOxlXxcWBTdt9woaz-iIF_hfWISuqc0veQv6jO1_77c1lWZ3KeLjOMTHf9P59FFjetBG0lGnjK8ww8DZbYHr-Uj-jfRkhJMiVqHKUtW5SAFz6NoMaOP33lEc3-80BZi1BAWETOdAl3a1XdJBymO_XR1oG_YP8JR5eLP-r2GWYTzW6Wsgzu4Wk48fU5yGymmNW-TdpN4OaiDtyQKh0M--K6u0Qzxr65yXsxrJNMgSOUnrpdO54Ccg675VG0edtNlRW9bIHRcQGrjsAhq1JsQ8Ig80okkbPb6squc96cw6_MB2wQWjug

# 将失败，由于user haitao只拥有user角色
curl 'http://localhost:8081/admin/hello' -H "authorization: bearer $ACCESS_TOKEN" -v

# 成功，因为user haitao访问/user/hello
curl 'http://localhost:8081/user/hello' -H "authorization: bearer $ACCESS_TOKEN" -v
```
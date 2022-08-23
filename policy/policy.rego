package envoy.authz

import input.attributes.request.http as http_request

default allow := false

allow {
    is_token_valid
    action_allowed
}

is_token_valid {
    token.valid
    now := time.now_ns() / 1000000000
    now < token.payload.exp
}

action_allowed {
    http_request.method == "GET"
    
    # 如果用户拥有app-admin角色，则通过
    token.payload.resource_access[_].roles[_] == "app-admin"
}

action_allowed {
    http_request.method == "GET"

    # 如果用户拥有app-user角色，则通过
    token.payload.resource_access[_].roles[_] == "app-user"

    parts := split(input.attributes.request.http.path, "/")
    # 如果访问路径是/user，则通过
    parts[1] == "user"
}

# 定义function jwks_request
jwks_request(url) = http.send({
    "url": url,
    "method": "GET",
    "force_cache": true,
    "force_cache_duration_seconds": 3600 # Cache response for an hour
})

# 获取jwks
jwks = jwks_request("http://10.200.10.1:8080/realms/master/protocol/openid-connect/certs").body

token := {"valid": valid, "header": header, "payload": payload} {
    [_, encoded] := split(http_request.headers.authorization, " ")
    
    # 首先验证JWT token有效性，如果使用Spring Security验证的话，可忽略此步骤
    valid := io.jwt.verify_rs256(encoded, json.marshal(jwks))
    
    # 解码JWT token
    [header, payload, _] := io.jwt.decode(encoded)

    # 核对签发者
    payload.iss == "http://10.200.10.1:8080/realms/master"
}


package com.security.demo.backend.controller;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth2") // 与授权服务器接口路径一致
@Tag(name = "OAuth2 授权接口", description = "授权服务器内置接口（获取Token、验证Token等）")
public class OAuth2DocController {

    /**
     * 手动描述 /oauth2/token 接口（获取访问令牌）
     */
    @PostMapping("/token")
    @Operation(
            summary = "获取访问令牌",
            description = "支持 client_credentials 等授权类型，需通过 Basic Auth 传递客户端信息",
            parameters = {
                    @Parameter(name = "grant_type", in = ParameterIn.QUERY, required = true, description = "授权类型，如 client_credentials"),
                    @Parameter(name = "scope", in = ParameterIn.QUERY, description = "权限范围，如 read")
            },
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "成功返回Token",
                            content = @Content(
                                    examples = @ExampleObject(
                                            value = "{\n" +
                                                    "  \"access_token\": \"eyJraWQiOiI...\",\n" +
                                                    "  \"token_type\": \"Bearer\",\n" +
                                                    "  \"expires_in\": 3600,\n" +
                                                    "  \"scope\": \"read\"\n" +
                                                    "}"
                                    )
                            )
                    )
            }
    )
    public void getToken() {
        // 仅用于Swagger文档展示，实际接口由授权服务器提供
    }

    /**
     * 手动描述 /oauth2/introspect 接口（验证Token有效性）
     */
    @PostMapping("/introspect")
    @Operation(
            summary = "验证Token有效性",
            description = "检查access_token是否有效，需通过 Basic Auth 传递客户端信息",
            parameters = {
                    @Parameter(name = "token", in = ParameterIn.QUERY, required = true, description = "需要验证的access_token")
            },
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Token验证结果",
                            content = @Content(
                                    examples = @ExampleObject(
                                            value = "{\n" +
                                                    "  \"active\": true,\n" +
                                                    "  \"scope\": \"read\",\n" +
                                                    "  \"client_id\": \"client1\"\n" +
                                                    "}"
                                    )
                            )
                    )
            }
    )
    public void introspectToken() {
        // 仅用于Swagger文档展示
    }
}

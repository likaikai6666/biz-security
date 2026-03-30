package com.security.demo.backend.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecuritySchemes;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
// 文档基本信息配置
@OpenAPIDefinition(
        info = @Info(
                title = "加解密、授权、签名Demo",
                version = "1.0.0",
                description = "加解密、授权、签名文档1.0.0"
        )
)
@SecuritySchemes({
        @io.swagger.v3.oas.annotations.security.SecurityScheme(
                name = "basicAuth",
                type = io.swagger.v3.oas.annotations.enums.SecuritySchemeType.HTTP,
                scheme = "basic"
        ),
        // 2. Bearer Token：用于业务接口的访问认证（携带 access_token）
        @io.swagger.v3.oas.annotations.security.SecurityScheme(
                name = "bearerAuth",
                type = io.swagger.v3.oas.annotations.enums.SecuritySchemeType.HTTP,
                scheme = "bearer",
                bearerFormat = "JWT"
        )
})
public class SwaggerConfig {

    // 配置 OpenAPI 模型，与注解配置对应
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes("basicAuth",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("basic"))
                        .addSecuritySchemes("bearerAuth",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")))
                // 全局绑定 basicAuth，所有接口默认需要该认证
                .addSecurityItem(new SecurityRequirement().addList("basicAuth"));
    }
}
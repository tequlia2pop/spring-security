# Spring Security 介绍

## 简介

Spring Security 是为基于 Spring 的应用程序提供声明式安全保护的安全性框架。Spring Security 提供了完整的安全性解决方案，它能够在 Web 请求级别和方法调用级别处理身份认证和授权。

Spring Security 从两个角度来解决安全性问题：

* 使用 Servlet Filter 保护 Web 请求并限制 URL 级别的访问。
* 使用 Spring AOP 保护方法调用 —— 借助于对象代理和使用通知，能够确保只有具备适当权限的用户才能访问安全保护的方法。

---

Web 应用的潜在的脆弱性：

* 跨域脚本
* 伪造请求
* 会话劫持

安全包括两个主要操作， “认证”和“验证”（或权限控制）。 “认证” 是为用户建立一个他所声明的主体的过程， （“主体”一般是指用户、设备或可以在你系统中执行行动的其他系统）。 “验证”指的一个用户能否在你的应用中执行某个操作。 在到达授权判断之前，身份的主体已经由身份验证过程建立了。 

Spring Security 广泛支持各种身份验证模式，目前支持认证一体化和如下认证技术：

* Form-based authentication（基于表单的认证）

有时基本的认证是不够的。 有时你需要根据在主体和应用交互的方式来应用不同的安全措施。 

* HTTPS
* 整合 jcaptcha 一体化进行人类用户检测

Spring Security 不仅提供认证功能，也提供了完备的授权功能。在授权方面主要有三个领域，授权 Web 请求、授权被调用方法、授权访问单个对象的实例。 

## 项目模块

模块 | 包 |描述
--- | -- | ----
核心（Core） | spring-security-core.jar | 提供 Spring Security 基本库
Web | spring-security-web.jar | 提供了 Spring security 基于 Filter 的 Web 安全性支持
配置（Configuration） | spring-security-config.jar | 包含通过XML 和 Java 配置 Spring Security 的功能支持
LDAP | spring-security-ldap.jar | 支持基于 LDAP 进行认证
ACL | spring-security-acl.jar | 支持通过访问控制列表（access control list）为域对象提供安全性
CAS 客户端（CAS Client） | spring-security-cas-client.jar | 提供与 Jasig 的中心认证服务（Central Authentication Service, CAS）进行集成的功能
切面（Aspects） | ... | 当使用 Spring Security 注解时，会使用基于 AspectJ 的切面，而不是使用标准的 Spring AOP
加密（Cryptography） | ... | 提供了加密和密码编码的功能
OpenID | ... | 支持使用 OpenID 进行集中式认证
Remoting | ... | 提供了对 Spring Remoting 的支持
标签库（Tag Libraty） | ... | Spring Security 的 JSP 标签库

## 过滤 Web 请求

要通过 Spring Security 来过滤 Web 请求，应该配置一个 `DelegatingFilterProxy` 来拦截发往应用中的请求，并将请求委托给 ID 为 `springSecurityFilterChain` 的 bean。`DelegatingFilterProxy` 是一个特殊的 Servlet Filter，它可以链接一个或多个其他的 Filter。Spring Security 依赖一系列的 Servlet Filter 来提供不同的安全特性。

```java
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

public class SecurityWebInitializer extends AbstractSecurityWebApplicationInitializer {
}
```

Spring 会使用 `AbstractSecurityWebApplicationInitializer` bean 在 Web 容器中注册 `DelegatingFilterProxy`。它会为应用程序中的每个 URL 自动注册 `springSecurityFilterChain` Filter。

```xml
<filter>
  <filter-name>springSecurityFilterChain</filter-name>
  <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>

<filter-mapping>
  <filter-name>springSecurityFilterChain</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

## 编写简单的安全性配置

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;

// 启用 Spring MVC 安全性
@EnableWebMvcSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {}
```

```xml
<http auto-config='true'>
    <intercept-url pattern="/**" access="ROLE_USER" />
</http>
```

## 选择查询用户详细信息的服务

### 使用基于内存的用户存储

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;

@Configuration
@EnableWebMvcSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			// 使用基于内存的用户存储
			.inMemoryAuthentication()//
				// 添加用户 "user"，设置密码为 "password"，并为他授予 "USER" 角色
				.withUser("user").password("password").roles("USER").and()//
				// 添加用户 "admin"，设置密码为 "password"，并为他授予 "USER" 和 "ADMIN" 两个角色
				.withUser("admin").password("password").roles("USER", "ADMIN");
	}
}
```

注意：`roles()` 方法是 `authorities()` 的简写形式。`roles()` 方法所给定的值都会添加一个 "ROLE_" 前缀，并将其作为权限授予给用户。

```xml
<authentication-manager>
    <authentication-provider>
      <user-service>
        <user name="jimi" password="jimispassword" authorities="ROLE_USER, ROLE_ADMIN" />
        <user name="bob" password="bobspassword" authorities="ROLE_USER" />
      </user-service>
    </authentication-provider>
  </authentication-manager>
```

### 基于数据库表进行认证

```java
@Autowired
DataSource dataSource;

@Override
public void configure(AuthenticationManagerBuilder auth) throws Exception {
	auth
		// 基于数据库表进行认证
		.jdbcAuthentication()//
			.dataSource(dataSource)// 使用以 JDBC 为支撑的用户存储
			.usersByUsernameQuery(
				"select username, password, true from spitter where username=?")// 重写认证的查询语句
			.authoritiesByUsernameQuery(
				"select username, 'ROLE_USER' from spitter where username=?")// 重写基本权限的查询语句
			// .groupAuthoritiesByUsername("")// 重写群组权限的查询语句
			// .passwordEncoder(new StandardPasswordEncoder("53cr3t"))// 使用转码后的密码
	;
}
```

```xml
<authentication-manager>
    <authentication-provider>
      <jdbc-user-service data-source-ref="securityDataSource"/>
    </authentication-provider>
</authentication-manager>
```

关于标准的 Spring Security 用户数据表，参考 http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#user-schema

### 配置自定义的用户服务

如果要认证的用户存储在非关系型数据库中，如 `Mongo` 或 `Neo4j`，在这种情况下需要提供一个自定义的 `UserDetailsService` 接口实现。

**使用转码后的密码**

Spring Security 的加密模块包含实现：

## 拦截请求

用来定义如何保护路径的配置方法：

方法 | 作用
--- | ----
access(String) | 如果给定的 SpEL 表达式结算结果为 true，就允许访问
anonymous() | ...
authenticated() | 允许认证过的用户访问
denyAll() | ...
fullyAuthenticated() | ...
hasAnyAuthority(String...) | ...
hasAnyRole(String...) | ...
hasAuthority(String) | 如果用户具备给定权限的话，就允许访问
hasIpAddress(String) | ...
hasRole(String) | ...
not() | ...
permitAll() | ...
rememberMe() | ...

注意：匹配规则按照给定的顺序发挥作用。因此必须将最具体的请求路径放在前面，而最不具体的路径（如 `anyRequest()`）放在最后面。如果不这样做的话，那不具体的路径配置将会覆盖掉更为具体的路径配置。

### 使用 Spring 表达式进行安全保护

Spring Security 通过一些安全性相关的表达式扩展了 Spring 表达式语言：

安全表达式 | 计算结果
-------- | --------
authentication | 用户的认证对象
principal | 用户的 principal 对象
hasRole([role]) | 如果用户被授予了指定的角色，结果为 true
hasAnyRole([role1,role2]) | 如果用户被授予了列表中任意的指定角色，结果为 true
hasAuthority([authority]) | 如果当前 principal 具有指定的权限，则返回 `true`
hasAnyAuthority([authority1,authority2]) | 如果当前 principal 具有提供的任意角色（以逗号分隔的字符串列表形式给出），则返回 `true`
hasIpAddress(IP Address) | 如果请求来自指定 IP 的话，结果为 true
isAnonymous() | 如果当前用户为匿名用户，结果为 true
isAuthenticated() | 如果当前用户进行了认证的话，结果为 true
isFullyAuthenticated() | 如果当前用户进行了完整认证（不是通过 Remember-me 功能进行的认证），结果为 true
isRememberMe() | 如果当前用户是通过 Remember-me 功能自动认证的，结果为 true
permitAll() | 结果始终为 true
denyAll | 结果始终为 false
hasPermission(Object target, Object permission) | 根据给定的 permission，如果用户可以访问所提供的 target，则返回 `true`。例如，`hasPermission(domainObject, 'read')`
hasPermission(Object targetId, String targetType, Object permission) | 根据给定的 permission，如果用户可以访问所提供的 target，则返回 `true`。例如，`hasPermission(1, 'com.example.domain.Message', 'read')`

### 防止跨站请求伪造（CSRF）

防止跨站请求伪造的关键是要确保请求中的某些内容是恶意网站所无法提供的。Spring Security 通过一个同步 token 的方式来实现 CSRF 防护的功能。它将拦截状态变化的请求（例如，非 GET、HEAD、OPTIONS 和 TRACE 的请求），并检查 CSRF token。如果请求中不包含 CSRF token 的话，或者 token 不能与服务器端的 token 相匹配，请求将会失败，并抛出 `CsrfException` 异常。

使用 Spring Security CSRF 防护，步骤如下：

1. 使用正确的 HTTP 方法。具体来说，在使用 Spring Security 的 CSRF 支持之前，你需要确定你的应用程序使用 PATCH、POST、PUT 和/或 DELETE 来修改状态。

2. 配置 CSRF 防护。从 Spring 3.2 开始，Spring Security 默认启用 CSRF 防护。

	如果要禁用 CSRF 防护：

	```java
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable();
	}
	```
	
	```xml
	<http>
		<!-- ... -->
		<csrf disabled="true"/>
	</http>
	```

3. 引入 CSRF token。

	* 表单提交。所有的表单必须在一个 `_csrf` 域中提交 token，而且这个 token 必须要与服务器端计算并存储的 token 一致。
		* JSP
		
		```jsp
		<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
		```

		更容易的方法是使用 Spring Security JSP 标签库的 `csrfInput` 标签：

		```jsp
		<secure:csrfInput />
		```

		* 如果使用 Spring MVC 的 `<form:form>` 标签，或使用 Thymeleaf 模板（在 `<form>` 标签中使用 `th:action`），会自动添加隐藏的 CSRF token 标签。
		
	* Ajax 和 JSON 请求
	* CookieCsrfTokenRepository

## 认证用户

### 配置表单登录

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
		// 配置表单登录
		// 这里提供一个自定义的登录页面，而不是使用默认的登录页
		.formLogin()// 支持基于表单的认证（启用默认的登录页）
			.loginPage("/login")// 指定登录页面的位置，默认为 "/login"
		.and()
		...
	;
}
```

```xml
<http auto-config='true'>
	<intercept-url pattern="/login.jsp*" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
	<intercept-url pattern="/**" access="ROLE_USER" />
	<form-login login-page='/login.jsp'/>
</http>
```

```xml
<http auto-config='true'>
    <intercept-url pattern="/css/**" filters="none"/>
    <intercept-url pattern="/login.jsp*" filters="none"/>
    <intercept-url pattern="/**" access="ROLE_USER" />
    <form-login login-page='/login.jsp'/>
</http>
```

### 启用 HTTP Basic 认证

对于应用程序的人类用户来说，基于表单的认证是比较理想的。但是当应用程序的使用者是另外一个应用程序的话（例如将 Web 应用的页面转化为 RESTFul API），使用表单来提示登录的方式就不太适合了。

HTTP Basic（HTTP Basic Authentication）会直接通过 HTTP 请求本身，对要访问应用程序的用户进行认证。

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
		// 配置表单登录
		// 这里提供一个自定义的登录页面，而不是使用默认的登录页
		.formLogin()// 支持基于表单的认证（启用默认的登录页）
			.loginPage("/login")// 指定用于渲染登录页面的 URL
		.and()
		// 配置 HTTP Basic
		.httpBasic()// 支持 HTTP Basic 认证
			.realmName("Spitter")// 指定域
		.and()
		...
	;
}
```

```xml
<http auto-config='true'>
    <intercept-url pattern="/**" access="ROLE_USER" />
    <http-basic />
</http>
```

### 启用 Remember-me 功能

默认情况下，Remember-me 是通过在 cookie 中存储一个 token 完成的。这个 token 包含用户名、密码、过期时间和一个私钥。过期时间为两周，私钥的名为一个随机生成的安全值。

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
			// 配置表单登录
			// 这里提供一个自定义的登录页面，而不是使用默认的登录页
			.formLogin()// 支持基于表单的认证（启用默认的登录页）
			.loginPage("/login")// 指定登录页面的位置

			// 配置退出行为
			.and()//
			.logout()// 支持退出
			// .logoutUrl("/signout")// 触发退出的 URL
			.logoutSuccessUrl("/")// 退出成功后重定向的 URL

			// 配置 Remember-me
			.rememberMe()// 支持 Remember-me 认证
				.tokenRepository(new InMemoryTokenRepositoryImpl())//
			.tokenValiditySeconds(2419200)// 指定 token 最多四周内有效
			.key("spittrKey")// 设置私钥的名称。默认值为 SpringSecured

			...
	;
}
```

```xml
<http>
    ...
    <remember-me key="myAppKey"/>
</http>
```

另外，登录请求必须包含一个名为 `remember-me` 的参数。在登录表单中，增加爱一个简单复选框就可以完成这件事情：

```html
<input type="checkbox" id="remember_me" name="remember-me" /> 
<label for="remember_me" class="inline">Remember me</label>
```

### 配置退出行为

退出功能是通过 Filter（`LogoutFilter`） 实现的。默认情况下，访问 "/logout" URL 会退出应用，HTTP 会话将无效，Remember-me token 都会被清除。在退出完成后，用户浏览器将会重定向到 "login?logout"（"login?success"）。

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
		...

		// 配置退出行为
		.logout()// 支持退出
			.logoutUrl("/signout")// 触发退出的 URL，默认为 "/logout"
			.logoutSuccessUrl("/")// 退出成功后重定向的 URL，默认为 <form-login-login-page>/?logout（即 /login?logout）
			
			.logoutUrl("/logout")// 触发退出的 URL，默认为 "/logout"
			.logoutSuccessUrl("/login?logout")// 退出成功后重定向的 URL，默认为 <form-login-login-page>/?logout（即 /login?logout）
			.logoutSuccessHandler(logoutSuccessHandler)// 指定一个自定义的 `LogoutSuccessHandler`。如果指定了此参数，将忽略 `logoutSuccessUrl()`
			.invalidateHttpSession(true)// 指定在退出时是否使 HttpSession 失效。默认为 `true`
			.addLogoutHandler(logoutHandler)// 添加一个 `LogoutHandler`
			.deleteCookies("JSESSIONID")// 指定退出成功后要删除的 Cookie 名称

		...
	;
}
```

## 保护视图

当为浏览器渲染 HTML 内容时，你可能希望视图中能够反映安全限制和相关的信息。一个简单的样例就是渲染用户的基本信息。或者你向根据用户被授予了什么权限，有条件的渲染特定的视图元素。

* JPS 标签库
* Thymeleaf 的 Spring Security 方言

## 防护方法应用

除了保护应用的 Web 层以外，我们还需要考虑保护方法的安全性。这样就能保证如果用户不具备权限的话，就无法执行相应的逻辑。

Spring Security 提供了三种不同的安全注解：

* Spring Security 自带的 `@Secured` 注解
* JSR-250 的 `RolesAllowed` 注解
* 表达式驱动的注解，包括 `@PreAuthorize`、`@PostAuthorize`、`@PreFilter` 和 `@PostFilter`

### 使用 `@Secured` 注解

启用基于注解的方法安全性：

```java
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    // ...
}
```

将 `securedEnabled` 设置为 `true` 后将会创建一个切点，这样的话 Spring Security 切面就会包装带有 `@Secured` 注解的方法。

如果方法被没有认证的用户或没有所需权限的用户调用，保护这个方法的切面将抛出一个 Spring Security 异常（可能是 AuthenticationException 或  AccessDeniedException 的子类）。

通过覆盖 `GlobalMethodSecurityConfiguration` 父类的方法，可以为方法级别的安全性提供更精细的配置，包括认证，以及提供一些自定义的安全表达式处理行为。 

### 使用 `RolesAllowed` 注解

启用基于注解的方法安全性：

```java
@Configuration
@EnableGlobalMethodSecurity(jsr250Enabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
	// ...
}
```

### 使用表达式实现方法级别的安全性

启用基于注解的方法安全性：

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
	// ...
}
```

```xml
<global-method-security pre-post-annotations="enabled" />
```

注解 | 描述
--- | ----
`@PreAuthorize` | 在方法调用前，基于表达式的结算结果来限制对方法的访问
`@PostAuthorize` | 允许方法调用，但是如果表达式计算结果为 false，将抛出一个安全性异常
`@PreFilter` | 允许方法调用，但必须在进入方法之前过滤输入值
`@PostFilter` | 允许方法调用，但必须按照表达式来过滤方法的结果

Spring Security 在 SpEL 中额外提供的变量：

* `targetObject`：要计算的集合或数组中的当前元素。
* `returnObject`：方法的返回值。
* `filterTarget`
* `filterObject`：方法所返回的集合或数组中的当前元素。

**定义许可计算器（PermissionEvaluator）**

在注解中使用表达式可能会很笨重、复杂且难以测试。

如果要在业务方法中应用以下的安全限制：

```java
@Secured({ "ROLE_USER", "ROLE_ADMIN" })
// @PreFilter("hasRole('ROLE_ADMIN') || targetObject.spitter.username == principal.username")
@PreFilter("hasPermission(targetObject, 'delete')")
void deleteSpittles(List<Spittle> spittles);
```

`hasPermission()` 函数是 Spring Security 为 SpEL 提供的扩展，它为开发者提供了一个时机，能够在执行计算的时候插入任意的逻辑。我们所需要做的就是编写并注册一个自定义的许可计算器，包含了表达式逻辑。

1. 自定义许可计算器

	```java
	public class SpittlePermissionEvaluator implements PermissionEvaluator {
	
		private static final GrantedAuthority ADMIN_AUTHORITY = new SimpleGrantedAuthority(
				"ROLE_ADMIN");
	
		@Override
		public boolean hasPermission(Authentication authentication, Object targetDomainObject,
				Object permission) {
			if (targetDomainObject instanceof Spittle) {
				Spittle spittle = (Spittle) targetDomainObject;
				String username = spittle.getSpitter().getUsername();
				if ("delete".equals(permission)) {
					return isAdmin(authentication) || username.equals(authentication.getName());
				}
			}
	
			throw new UnsupportedOperationException("hasPermission not supported for object <"
					+ targetDomainObject + "> and permission <" + permission + ">");
		}
	
		@Override
		public boolean hasPermission(Authentication authentication, Serializable targetId,
				String targetType, Object permission) {
			throw new UnsupportedOperationException();
		}
	
		/**
		 * 检查指定的用户认证对象是否具有 ADMIN 权限。
		 * 
		 * @param authentication
		 * @return
		 */
		private boolean isAdmin(Authentication authentication) {
			return authentication.getAuthorities().contains(ADMIN_AUTHORITY);
		}
	
	}
	```

2. 注册许可计算器

	```java
	/*
	 * 替换原有的表达式处理器，换成使用自定义许可计算器的表达式处理器。
	 * @see org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration#createExpressionHandler()
	 */
	@Override
	protected MethodSecurityExpressionHandler createExpressionHandler() {
		DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		expressionHandler.setPermissionEvaluator(new SpittlePermissionEvaluator());
		return expressionHandler;
	}
	```
	```xml
	<security:global-method-security pre-post-annotations="enabled">
		<security:expression-handler ref="expressionHandler"/>
	</security:global-method-security>
	
	<bean id="expressionHandler" class=
	"org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler">
		<property name="permissionEvaluator" ref="myPermissionEvaluator"/>
	</bean>
	```
	

## 附录 JSP 标签库

### 介绍

**声明标签库**

```xml
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
```

**JPS 标签介绍**

JSP 标签 | 作用 
------- | ---- 
`<securiry:accesscontrollist>` | 如果用户通过访问控制列表授予了指定的权限，那么渲染该标签体中的内容
`<security:authentication>` | 渲染当前用户认证对象的详细信息
`<security:authorize>` | 如果用户被授予了特定的权限或者 SpEL 表达式的计算结果为  true，那么渲染该标签体中的内容

### authentication 标签

authentication 标签用于访问认证信息的细节。

```xml
Hello <security:authentication property="principal.username" />!
```

### authorize 标签

authorize 标签支持条件性的渲染视图内容。

```xml
<sec:authorize access="hasRole('supervisor')">
只有在 <tt>GrantedAuthority</tt> 列表中具有 "supervisor" 权限的用户才能看到此内容。
</sec:authorize>
```

```xml
<sec:authorize access="hasPermission(#domain,'read') or hasPermission(#domain,'write')">
This content will only be visible to users who have read or write permission to the Object found as a request attribute named "domain".
</sec:authorize>
```

```xml
<sec:authorize url="/admin">
只有有权向 "/admin" URL 发送请求的用户才能看到此内容。
</sec:authorize>
```

## 附录 Spring MVC 集成

* @EnableWebMvcSecurity

	NOTE: 从 Spring Security 4.0 开始，不推荐使用 `@EnableWebMvcSecurity`。替换是 `@EnableWebSecurity`，它将确定添加基于类路径的 Spring MVC 功能。

* MvcRequestMatcher

	```java
	protected configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.mvcMatchers("/admin").hasRole("ADMIN");
	}
	```

* @AuthenticationPrincipal

* Spring MVC 异步集成
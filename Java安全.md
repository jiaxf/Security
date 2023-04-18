[返回目录](代码安全检查.md)

## Java安全

Java语言开发需要注意的安全编码方案包括以下几点：

1. 避免使用已知的安全漏洞：在开发过程中，应该避免使用已知的安全漏洞，比如使用不安全的加密算法、使用不安全的网络协议等。
2. 防止SQL注入攻击：在编写SQL语句时，应该使用参数化查询，避免将用户输入的数据直接拼接到SQL语句中，从而防止SQL注入攻击。
3. 防止跨站脚本攻击：在编写Web应用程序时，应该对用户输入的数据进行过滤和转义，避免将恶意脚本注入到页面中，从而防止跨站脚本攻击。
4. 避免使用不安全的密码存储方式：在存储用户密码时，应该使用安全的密码存储方式，比如使用哈希函数和盐值来加密密码，避免使用明文存储密码。
5. 避免使用不安全的文件上传方式：在允许用户上传文件时，应该对上传的文件进行检查和过滤，避免上传恶意文件，从而防止文件上传漏洞攻击。

总之，Java语言开发需要注意安全编码方案，避免使用已知的安全漏洞，使用安全的编码方式来保护应用程序的安全性。以下是具体建议：

### I. 代码实现

#### 1.1 数据持久化

##### 1.1.1【必须】SQL语句默认使用预编译并绑定变量

Web后台系统应默认使用预编译绑定变量的形式创建sql语句，保持查询语句和数据相分离。以从本质上避免SQL注入风险。

如使用Mybatis作为持久层框架，应通过\#{}语法进行参数绑定，MyBatis 会创建 `PreparedStatement` 参数占位符，并通过占位符安全地设置参数。

示例：JDBC

```java
String custname = request.getParameter("name"); 
String query = "SELECT * FROM user_data WHERE user_name = ? ";
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, custname); 
ResultSet results = pstmt.executeQuery( );
```

Mybatis

```java
<select id="queryRuleIdByApplicationId" parameterType="java.lang.String" resultType="java.lang.String">    
      select rule_id from scan_rule_sqlmap_tab where application_id=#{applicationId} 
</select>

```

应避免外部输入未经过滤直接拼接到SQL语句中，或者通过Mybatis中的${}传入SQL语句（即使使用PreparedStatement，SQL语句直接拼接外部输入也同样有风险。例如Mybatis中部分参数通过${}传入SQL语句后实际执行时调用的是PreparedStatement.execute()，同样存在注入风险）。

##### 1.1.2【必须】白名单过滤

对于表名、列名等无法进行预编译的场景，比如外部数据拼接到order by, group by语句中，需通过白名单的形式对数据进行校验，例如判断传入列名是否存在、升降序仅允许输入“ASC”和“DESC”、表名列名仅允许输入字符、数字、下划线等。参考示例：

```java
public String someMethod(boolean sortOrder) {
 String SQLquery = "some SQL ... order by Salary " + (sortOrder ? "ASC" : "DESC");`
 ...
```

#### 1.2 文件操作

##### 1.2.1【必须】文件类型限制

须在服务器端采用白名单方式对上传或下载的文件类型、大小进行严格的限制。仅允许业务所需文件类型上传，避免上传.jsp、.jspx、.class、.java等可执行文件。参考示例：

```java
       String file_name = file.getOriginalFilename();
        String[] parts = file_name.split("\\.");
        String suffix = parts[parts.length - 1];
        switch (suffix){
            case "jpeg":
                suffix = ".jpeg";
                break;
            case "jpg":
                suffix = ".jpg";
                break;
            case "bmp":
                suffix = ".bmp";
                break;
            case "png":
                suffix = ".png";
                break;
            default:
                //handle error
                return "error";
        }
```

##### 1.2.2【必须】禁止外部文件存储于可执行目录

禁止外部文件存储于WEB容器的可执行目录（appBase）。建议保存在专门的文件服务器中。

##### 1.2.3【建议】避免路径拼接

文件目录避免外部参数拼接。保存文件目录建议后台写死并对文件名进行校验（字符类型、长度）。建议文件保存时，将文件名替换为随机字符串。

##### 1.2.4【必须】避免路径穿越

如因业务需要不能满足1.2.3的要求，文件路径、文件命中拼接了不可行数据，需判断请求文件名和文件路径参数中是否存在../或..\\(仅windows)， 如存在应判定路径非法并拒绝请求。

#### 1.6 OS命令执行

##### 1.6.1【建议】避免不可信数据拼接操作系统命令

当不可信数据存在时，应尽量避免外部数据拼接到操作系统命令使用 `Runtime` 和 `ProcessBuilder` 来执行。优先使用其他同类操作进行代替，比如通过文件系统API进行文件操作而非直接调用操作系统命令。

##### 1.6.2【必须】避免创建SHELL操作

如无法避免直接访问操作系统命令，需要严格管理外部传入参数，使不可信数据仅作为执行命令的参数而非命令。

- 禁止外部数据直接直接作为操作系统命令执行。

- 避免通过"cmd"、“bash”、“sh”等命令创建shell后拼接外部数据来执行操作系统命令。

- 对外部传入数据进行过滤。可通过白名单限制字符类型，仅允许字符、数字、下划线；或过滤转义以下符号：|;&$><`（反引号）\!

  白名单示例：

  ```java
  private static final Pattern FILTER_PATTERN = Pattern.compile("[0-9A-Za-z_]+");
  if (!FILTER_PATTERN.matcher(input).matches()) {
    // 终止当前请求的处理
  }
  ```

#### 1.7 会话管理

##### 1.7.1【必须】非一次有效身份凭证禁止在URL中传输

身份凭证禁止在URL中传输，一次有效的身份凭证除外（如CAS中的st）。

##### 1.7.2【必须】避免未经校验的数据直接给会话赋值

防止会话信息被篡改，如恶意用户通过URL篡改手机号码等。

#### 1.8 加解密

##### 1.8.1【建议】对称加密

建议使用AES，秘钥长度128位以上。禁止使用DES算法，由于秘钥太短，其为目前已知不安全加密算法。使用AES加密算法请参考以下注意事项：

- AES算法如果采用CBC模式：每次加密时IV必须采用密码学安全的伪随机发生器（如/dev/urandom）,禁止填充全0等固定值。
- AES算法如采用GCM模式，nonce须采用密码学安全的伪随机数
- AES算法避免使用ECB模式，推荐使用GCM模式。

##### 1.8.2【建议】非对称加密

建议使用RSA算法，秘钥2048及以上。

##### 1.8.3【建议】哈希算法

哈希算法推荐使用SHA-2及以上。对于签名场景，应使用HMAC算法。如果采用字符串拼接盐值后哈希的方式，禁止将盐值置于字符串开头，以避免哈希长度拓展攻击。

##### 1.8.4【建议】密码存储策略

建议采用随机盐+明文密码进行多轮哈希后存储密码。

#### 1.9 查询业务

##### 1.9.1【必须】返回信息最小化

返回用户信息应遵循最小化原则，避免将业务需求之外的用户信息返回到前端。

##### 1.9.2【必须】个人敏感信息脱敏展示

在满足业务需求的情况下，个人敏感信息需脱敏展示,如：

- 鉴权信息（如口令、密保答案、生理标识等）不允许展示
- 身份证只显示第一位和最后一位字符，如3****************1。
- 移动电话号码隐藏中间6位字符，如134******48。
- 工作地址/家庭地址最多显示到“区”一级。
- 银行卡号仅显示最后4位字符，如************8639 

##### 1.9.3【必须】数据权限校验

查询个人非公开信息时，需要对当前访问账号进行数据权限校验。

1. 验证当前用户的登录态
2. 从可信结构中获取经过校验的当前请求账号的身份信息（如：session）。禁止从用户请求参数或Cookie中获取外部传入不可信用户身份直接进行查询。
3. 验当前用户是否具备访问数据的权限

#### 1.10 操作业务

##### 1.10.1【必须】部署CSRF防御机制

CSRF是指跨站请求伪造（Cross-site request forgery），是web常见的攻击之一。对于可重放的敏感操作请求，需部署CSRF防御机制。可参考以下两种常见的CSRF防御方式

- 设置CSRF Token

  服务端给合法的客户颁发CSRF Token，客户端在发送请求时携带该token供服务端校验，服务端拒绝token验证不通过的请求。以此来防止第三方构造合法的恶意操作链接。Token的作用域可以是Request级或者Session级。下面以Session级CSRF Token进行示例

  1. 登录成功后颁发Token，并同时存储在服务端Session中

     ```java
     String uuidToken = UUID.randomUUID().toString();
     map.put("token", uuidToken);
     request.getSession().setAttribute("token",uuidToken );
     return map;
     ```

     

  2. 创建Filter

     ```java
     public class CsrfFilter implements Filter {  
       ...
        HttpSession session = req.getSession();
        Object token = session.getAttribute("token");
        String requestToken = req.getParameter("token");
        if(StringUtils.isBlank(requestToken) || !requestToken.equals(token)){
              AjaxResponseWriter.write(req, resp, ServiceStatusEnum.ILLEGAL_TOKEN, "非法的token");
                 return;
             }
        ...
     ```

  ​     CSRF Token应具备随机性，保证其不可预测和枚举。另外由于浏览器会自动对表单所访问的域名添加相应的cookie信息，所以CSRF Token不应该通过Cookie传输。

  ​    

- 校验Referer头

  通过检查HTTP请求的Referer字段是否属于本站域名，非本站域名的请求进行拒绝。

  这种校验方式需要注意两点：

  1. 要需要处理Referer为空的情况，当Referer为空则拒绝请求
  2. 注意避免例如qq.com.evil.com 部分匹配的情况。

##### 1.10.2【必须】权限校验

对于非公共操作，应当校验当前访问账号进行操作权限（常见于CMS）和数据权限校验。

1. 验证当前用户的登录态
2. 从可信结构中获取经过校验的当前请求账号的身份信息（如：session）。禁止从用户请求参数或Cookie中获取外部传入不可信用户身份直接进行查询。
3. 校验当前用户是否具备该操作权限
4. 校验当前用户是否具备所操作数据的权限。避免越权。

##### 1.10.3【建议】加锁操作

对于有次数限制的操作，比如抽奖。如果操作的过程中资源访问未正确加锁。在高并发的情况下可能造成条件竞争，导致实际操作成功次数多于用户实际操作资格次数。此类操作应加锁处理。


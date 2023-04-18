[返回目录](README.md)


### 常见的安全checklist类型

1. SQL 注入:对用户输入的数据进行过滤和验证,避免直接拼接到 SQL 语句中导致 SQL 注入漏洞。
2. XSS 攻击:对于用户输入的 HTML、CSS 和 JavaScript 代码进行过滤和编码,避免输出到页面导致 XSS 攻击。
3. CSRF 攻击:为所有操作请求设置 token,并验证 token 的有效性和正确性,避免 CSRF 攻击。
4. 身份认证和授权:使用足够复杂的密码来保护用户账户安全,对敏感数据和操作设置正确的权限控制。
5. 敏感数据处理:对于敏感数据如密码、银行卡号、信用卡号在存储和传输时进行加密,避免被盗取和滥用。
6. 漏洞修复:及时关注并安装软件依赖的安全补丁,修复潜在的漏洞,特别关注网络接口所使用的框架。
7. 不安全的依赖:注意检查项目中使用的第三方依赖或开源组件,避免使用那些已知存在安全漏洞的组件版本。
8. 权限控制:避免程序使用高权限用户运行,权限应该越小越好,不同模块使用独立的权限用户运行。
9. 日志记录:记录程序运行和用户操作的日志信息,可以用于事后安全审计和追踪漏洞利用。但日志信息也要保护好,避免泄露。
10. 测试安全性:在开发测试时增加对常见 web 攻击方式的测试,比如 SQL 注入、XSS 和 CSRF 等,确保程序存在漏洞再上线。
11. 其他:还有缓存控制、错误和异常处理、加密传输等也是安全checklist中需要关注的点。

以下是常见的一些实际应用关注点：

##### 权限系统 (注册/登录/二次验证/密码重置)
-  任何地方都使用 HTTPS.
-  使用 `Bcrypt` 存储密码哈希
-  `登出`之后销毁会话 ID .  
-  密码重置后销毁所有活跃的会话.  
-  OAuth2 验证必须包含 `state` 参数.
-  登陆成功之后不能直接重定向到开放的路径（需要校验，否则容易存在钓鱼攻击）.
-  当解析用户注册/登陆的输入时，过滤 javascript://、 data:// 以及其他 CRLF 字符.
-  使用 secure/httpOnly cookies.
-  移动端使用 `OTP` 验证时，当调用 `generate OTP` 或者 `Resend OTP` API 时不能把 OTP（One Time Password） 直接返回。（一般是通过发送手机验证短信，邮箱随机 code 等方式，而不是直接 response）  
-  限制单个用户 `Login`、`Verify OTP`、 `Resend OTP`、`generate OTP` 等 API 的调用次数，使用 Captcha 等手段防止暴力破解.  
-  检查邮件或短信里的重置密码的 token，确保随机性（无法猜测）  
-  给重置密码的 token 设置过期时间.
-  重置密码成功后，将重置使用的 token 失效.

    注：
    1. Bcrypt是一种密码哈希函数，它是由Niels Provos和David Mazières设计的。Bcrypt使用一种称为“Adaptive Hashing”的技术，它可以在计算机速度增加时增加哈希函数的复杂度，以防止暴力破解攻击。
    Bcrypt采用的是哈希和盐值（salt）相结合的技术。哈希是一种将任意长度的消息压缩成固定长度输出的技术，其目的是将密码变成一个看起来毫无意义的字符串。而盐值可以进一步增加哈希的安全性，因为它是随机生成的一段字符串，将与原始密码结合起来进行哈希计算，从而使得攻击者无法轻易破解密码。
    Bcrypt的特点是安全性高、哈希计算较慢，破解成本较高，而且可以自适应提高哈希计算的复杂度以增加安全性。它广泛用于网络应用中对密码的存储和验证。许多安全专家和密码学家推荐使用Bcrypt作为存储密码的标准。
    
    2. OTP（One-Time Password）即一次性密码，是一种动态口令技术，用于在移动端应用中进行身份验证。一次性密码指的是只能使用一次的密码。 OTP验证一般是通过文字短信、手机应用程序或硬件设备等方式将一次性密码发送到用户手机上，用户再将该密码输入到移动端应用中进行验证。因为密码只能使用一次，所以即使被非法获取也无法再次使用。
    OTP的优点在于它可以为用户提供高度安全的身份验证，因为每次都生成不同的密码，攻击者很难通过猜测、强行计算或重放攻击来破解密码。 OTP还可以增加移动应用的安全性，因为即使攻击者盗取了用户的密码，他们也无法通过该密码访问帐户。此外，OTP还可以随时禁用或更改，进一步提高了身份验证的安全性。
    OTP验证在移动端应用中非常常见，尤其是在需要高度安全性的应用程序中，例如银行、支付、电子邮件、社交媒体和医疗保健应用程序等。OTP验证技术的发展也在不断推进，许多应用程序现在已经可以使用更安全、更高效的 OTP验证方式，例如使用蓝牙或NFC连接的硬件设备生成 OTP。
    
    3. Captcha（全称“Completely Automated Public Turing test to tell Computers and Humans Apart”）是一种用于验证用户是否为人类而不是机器的技术，通常用于防止恶意机器人或自动化脚本访问和攻击计算机系统。
    Captcha技术通过在网站上显示一个包含随机文字或数字的图片或视频流并要求用户输入这些字符来进行验证。这些字符会经过扭曲、斜体、旋转、扭曲等处理以防止机器识别。由于机器难以对扭曲的字符进行识别，因此只有真正的人类才能正确地输入这些字符。
    Captcha技术在网站安全中扮演着重要的角色，它可以帮助网站管理员识别恶意机器人并保护网站不受机器人攻击的影响。现在有很多种不同类型的Captcha技术，包括图像识别、声音识别、数学问题等，它们都在不断发展和改进，以适应不断变化和发展的网络安全需求。


##### 用户数据和权限校验  
-  诸如`我的购物车`、`我的浏览历史`之类的资源访问，必须检查当前登录的用户是否有这些资源的访问权限.
-  避免资源 ID 被连续遍历访问，使用 `/me/orders` 代替 `/user/1234/orders` 以防你忘了检查权限，导致数据泄露。   
-  `修改邮箱/手机号码`功能必须首先确认用户已经验证过邮箱/手机是他自己的。  
-  任何上传功能应该过滤用户上传的文件名，另外，为了普适性的原因（而不是安全问题），上传的东西应该存放到例如 S3、OSS 之类的云存储上面(用 lambda 处理)，而不是存储在自己的服务器，防止代码执行。  
-  `个人头像上传` 功能应该过滤所有的 `EXIF` 标签，即便没有这个需求.  
-  用户 ID 或者其他的 ID，应该使用 [RFC compliant ](http://www.ietf.org/rfc/rfc4122.txt) 的 `UUID` 而不是整数.
-  [JWT（JSON Web Token）](https://jwt.io/)很棒.当你需要构建一个 单页应用/API 时使用.  


##### 安全头信息和配置  
-  `添加` [CSP](https://en.wikipedia.org/wiki/Content_Security_Policy) 头信息，减缓 XSS 和数据注入攻击.
-  `添加` [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) 头信息防止跨站请求伪造（CSRF）攻击.同时`添加` [SameSite](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00) 属性到 cookie 里面.
-  `添加` [HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) 头信息防止 SSL stripping 攻击.
-  `添加` 你的域名到 [HSTS 预加载列表](https://hstspreload.appspot.com/)
-  `添加` [X-Frame-Options](https://en.wikipedia.org/wiki/Clickjacking#X-Frame-Options) 防止点击劫持.
-  `添加` [X-XSS-Protection](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#X-XSS-Protection) 缓解 XSS 攻击.
-  `更新` DNS 记录，增加 [SPF](https://en.wikipedia.org/wiki/Sender_Policy_Framework) 记录防止垃圾邮件和钓鱼攻击.
-  如果你的 Javascript 托管在第三方的 CDN 上面，需要`添加` [内部资源集成检查](https://en.wikipedia.org/wiki/Subresource_Integrity) 。为了更加安全，添加[require-sri-for](https://w3c.github.io/webappsec-subresource-integrity/#parse-require-sri-for) CSP-directive 就不会加载到没有 SRI 的资源.
-  使用随机的 CSRF token，业务逻辑 API 可以暴露为 POST 请求。不要把 CSRF token 通过 http 接口暴露出来，比如第一次请求更新的时候.
-  在 get 请求参数里面，不要使用临界数据和 token。 暴露服务器日志的同时也会暴露用户数据.


##### 过滤输入  
-  所有暴露给用户的参数输入都应该 `过滤` 防止 [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting) 攻击.
-  使用参数化的查询防止 [SQL 注入](https://en.wikipedia.org/wiki/SQL_injection).  
-  过滤所有具有功能性的用户输入，比如 `CSV导入`.
-  `过滤`一些特殊的用户输入，例如将 robots.txt 作为用户名，而你刚好提供了 coolcorp.io/username 之类的 url 来提供用户信息访问页面。（此时变成 coolcorp.io/robots.txt，可能无法正常工作）  
-  不要自己手动拼装 JSON 字符串，不管这个对象有多么小。请使用你所用的语言相应的库或者框架来编写
-  `过滤` 那些有点像 URL 的输入，防止 [SSRF](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#heading=h.t4tsk5ixehdd) 攻击.
-  在输出显示给用户之前，`过滤`输出信息.

##### 操作建议
-  如果你的业务很小或者你缺乏经验，可以评估一下使用 AWS 或者一个 PaaS 平台来运行代码.
-  在云上使用正规的脚本创建虚拟机.
-  检查所有机器没有必要开放的`端口`.
-  检查数据库是否没有设置密码或者使用默认密码，特别是 MongoDB 和 Redis.
-  使用 SSH 登录你的机器，不要使用密码，而是通过 SSH key 验证来登录.
-  及时更新系统，防止出现 0day 漏洞，比如 Heartbleed、Shellshock 等.
-  修改服务器配置，HTTPS 使用 TLS1.2，禁用其他的模式。.
-  不要在线上开启 DEBUG 模式，有些框架，DEBUG 模式会开启很多权限以及后门，或者是暴露一些敏感数据到错误栈信息里面.
-  对坏人和 DDOS 攻击要有所准备，使用那些提供 DDOS 清洗的主机服务.
-  监控你的系统，同时记录到日志里面 (例如使用 [New Relic](https://newrelic.com/) 或者其他 ).



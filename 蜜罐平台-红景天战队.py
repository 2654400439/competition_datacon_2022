# coding=utf-8

from flask import Flask, request
from jinja2 import Template
import requests as REQ
import urllib3
import base64
import hashlib

urllib3.util.url.FRAGMENT_CHARS |= {"}", "{", "[", "]", "!", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "/"
                                                                                                               ":", ";",
                                    "=", "?", "@", "~"}

DATA = 'zgbaicmr'
DEFAULT_HEADERS = {"Content-Type": "text/plain; charset=utf-8"}

app = Flask(__name__)

from werkzeug.routing import BaseConverter


class RegexCoverter(BaseConverter):
    def __init__(self, url_map, *args):
        # super 重写父类
        super(RegexCoverter, self).__init__(url_map)
        # 将第一个接受的参数当作匹配规则进行保存
        self.regex = args[0]

    def to_python(self, value):
        '''
        该函数中的value值代表匹配的值，可以输出查看，
        当匹配完成之后，对匹配到参数作最后一步处理再返回
        '''
        return str(value)


app.url_map.converters['re'] = RegexCoverter

apache_default = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /sadasd was not found on this server.</p >
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 127.0.0.1 Port 9999</address>
</body></html>"""

other_default = """con_db_pass con_db_name con_db_host for 16-bit app support [extensions] bin:x:1:1:bin:/bin:/sbin/nologin root:x:0:0:root:/root:/bin/bash.kibanaWelcomeView" \xcf\xb5\xcd\xb3\xb9\xdc\xc0\xed\xd4\xb1\x7c <servlet-name>NCInvokerServlet</servlet-name>" user_token" PDOException userSession" require_once ('conversion.php'); <title>Airflow - DAGs</title> com.alibaba.otter.canal.admin.controller.UserController.login" userSession Manifest-Version: Fatal error: Call to a menber function add_event_listener() on a non-object in (?i)filename=.*?.csv mysql2i.func.php on line 10 文件管理 <title>Kafka Manager</title> passwd_change.ehp") name=admin Directory of / Fatal error: Cannot redeclare mysql_affected_rows() in header TmlnaHQgZ2F0aGVycywgYW5%kIG5vdyBteSB3YXRjaCBiZWdpbnMu1 success uid=0(root) \"data\":{\"token\"" Requested response schema not available confluence-init.properties <title>Nacos</title>") fae0b27c451c728867a567e8c1bb4e53" 46ea1712d4b13b55b3f680cc5b8b54e8 {\"result\": You Know, for Search passwd_change.ehp" Listing Load Balancing Worker Requested response schema not available" <result>OK</result>" Password:" Service,DateTime" <url-pattern>/weaver/" extensions webmaster level 2 username guest password guest") httpd_design_handlers context.php ba1f2511fc30423bdbb183fe33f3dd0f <firmwareVersion>" &#39;127.1.1.1&#39;, port: &#39;700&#39;") || respons VGhpbmtBZG1pbg") serverSparkVersion" [extensions]" org.couchdb.user:" + r1 Password: Swagger UI") || respons <h2>DAGs</h2>" <display-name>Confluence</display-name> /console/console.portal")) || respons 事件审计" fc9bdfb86bae5c322bae5acd78760935 VGhpbmtBZG1pbg" \"name\":\"guest\" \"password\":\"[a-f0-9]{32}\" {\"name\":\"root\",\"path\":\"/root\",\"folder\":true} com.atlassian.jira 81dc9bdb52d04dc20036dbd8313ed055 document.formParent2.changepasswd1.value" LoginForm.jsp" baidu.com" GateOne.init window.open('index.htm?_" right\">Router\\s*Admin\\s*Password< <title>电信网关服务器管理后台</title> encrypted=" success" config replicator_manager DB_USER Fatal error: Call to a menber function add_event_listener() on a non-object in" Excel.Sheet terminals/websocket window.open('index.htm?_ admin:x:0:0 <name> Service,DateTime") </usrid> com.alibaba.otter.canal.admin.controller.UserController.login \"identity\":\"anonymous\",\"anonymous\":true \"online_flag\": WeiPHP loggedIn \"pwd\":\"[0-9a-z]{32}\" left" var ModelName=\"DSL-2888A\"; user_token Install Progress DockerRootDir <param-name>contextConfigLocation</param-name>" / ../web-inf/ vendor\\laravel\\framework") || respons No such service [" + string(rand) \"agreed\":true" rdspassword= <url-pattern>/weaver/ /secure/ViewProfile.jspa?name=" + r {\"success\":\"true\", \"data\":{\"id\":1}, \"alert\":\"您正在使用默认密码登录，为保证设备安全，请立即修改密码\"} parent.doTestResult This file is managed by man:systemd-resolved(8). Do not edit." productTags" Generic H2" \"statusCode\":500" Name,Email,Status,Created 事件审计 db_host ^SQLite format 3\\x00\\x10 parent.doTestResult" \"name\":\"系统管理员\" external_manager username <name>Admin</name> user sql_error:MySQL Query Error {\"success\": true, \"msg\": \"OK\"} .ASPX View Default Decorator kong_db_cache_miss FileOutsidePaths" con_db_pass serverSparkVersion uid=0(root)" The TensorFlow Authors. All Rights Reserved." DB_NAME %@ page session=\"false\" import=\"com.caucho.vfs.*, com.caucho.server.webapp.*\" %" MetaLinkContainer" ~" + string(r1) + "~" <title>设备管理系统</title> <script>alert(1)" playback MMOneProfile" \"DisableRemoteExec\": false username" login success login_met_cookie($metinfo_admin_name);" strPasswd \"containerRuntimeVersion\" db_host" </web-app> java.lang.NullPointerException:null" $json_string = file_get_contents($fullpath); ef775988943825d2871e1cfa75473ec" dataexists" di.php %@ page session=\"false\" import=\"com.caucho.vfs.*, com.caucho.server.webapp.*\" %") <servlet-name>NCInvokerServlet</servlet-name>") os.arch <result>OK</result> /_app\": \".*?_app\\.js profile Manifest-Version:" URL=/cgi-bin/monitor.cgi ctpDataSource.password CDATA" <title>Dashboard</title>" URL=/index.htm The TensorFlow Authors. All Rights Reserved. (?i)SESSID=\\w{32} DruidDrivers URL=/cgi-bin/monitor.cgi" 扫描后门 manager" \"agreed\":true does not have valid YAML syntax") || respons 海康威视 <requestURL>/SDK/webLanguage</requestURL> salt/wheel/d* DB_PASSWORD  password=\" distributions" var ModelName=\"DSL-2888A\";" uid=0(admin) gid=0(admin)" States server_sql.php c4ca4238a0b923820dcc509a6f75849b JK Status Manager \"EnableScriptChecks\": true") || respons <param-name>contextConfigLocation</param-name> columns 'tip':'" /application/third_party/CIUnit/libraries/CIUnitTestCase.php on line" 审计管理员 logo-eoffice" index-shang.php org.couchdb.user:" + r1) <h2>DAGs</h2> encrypt passwords Vulnerable Fatal error: Class 'PHPUnit_Framework_TestCase' not found in  <username>(.*?)</username> kong_env" \"absolutePath\":\"/var/logs/ package#" + rand kong_env {\"code\":20000, not_authenticated <h2>Broker</h2> 6f7c6dcbc380aac3bcba1f9fccec99 uid <title>Spark total <script>alert 错误的id com.atlassian.jira") admin DruidVersion server_sql.php" Install Progress" $_GET['css'] hadoopVersion files" \xc4\xfa\xba\xc3\x7c\x7c\x7c admin:x:0:0" /Orion/NetPerfMon/TemplateSiblingIconUrl" document.title = LOGIN_BTN_LOGIN" {\"data\":\"0\",\"status\":1} {\"totalMem\": <script>alert(" + r1 + ");</script>" \"data\":{\"token\" custom_field1" <password>(.*?)</password> <roles>Anonymous</roles></roleList> for 16-bit app support" runner_async information_schema {\"acknowledged\":true} 6f7c6dcbc380aac3bcba1f9fccec99" \"result\":{\"success\":true}" Add Cluster baidu.com") files pass= login_met_cookie($metinfo_admin_name); vRealize Operations Manager" tomcat {\"name\":\"Windows\",\"path\":\"C:\\\\Windows\",\"folder\":true} runner_async" whoami : <SessionList>\r\n<Session>\r\n<usrID> playback" strUser 成功！" ncanal.aliyun.secretKey kylin.metadata.url SSLVPN_Resource con_db_host canonical" Call to undefined function helper()") name resolve order" href=\"/static/gateone.css\" Fatal error: Cannot redeclare mysql_affected_rows() in" Druid Stat Index jboss.web" H5_AUTO {\"result\":{\" zmmailboxd.out /_cat/master <user name=\" 文件管理" $certfile logo-eoffice.php uiVersion <%@ page session=\"false\" import=\"com.caucho.vfs.*, com.caucho.server.webapp.*\" %>" \xff\xd8\xff\xe1" (?m)(?:DROP|CREATE|(?:UN)?LOCK) TABLE|INSERT INTO \"name\":\"guest\"" Missing an action <object name=\"cm_md_db\">") Add Cluster" Welcome to H2 com.atlassian.jira" ADMIN <strong>URL:</strong> spark: org.postgresql.Driver AMBARI.ADMINISTRATOR id left.php root:[x*]:0:0: \"DisableRemoteExec\": false" \"id\":\"-7273032013234748168\"" failed to open stream") for 16-bit app support") || respons Unauthorized" URL=/index.htm" create user ok!" <rootManagerName> <title>安网科技-智能路由系统</title> {\"id\":1,\"params\":{\"keepAliveInterval\":60},\"result\":true,\"session\":\" www.ifw8.cn /seeyon/common/" This domain is for use in illustrative examples in documents. You may use this domain in literature without prior coordination or asking for permission." DruidDrivers" fc9bdfb86bae5c322bae5acd78760935"  password=\"" \"message\":\"Logged in\" jboss.web methodResponse" Discuz! info</b>: MySQL Query Error" 海康威视" [Content_Types].xml <rootManagerPassword> <a class=\"top-nav-zbbshare\" target=\"_blank\" title=\"Zabbix Share\" href=\"https://share.zabbix.com/\">Share</a>" \",\"email\":\"[^\"]+@[^\"]+\" c4ca4238a0b923820dcc509a6f75849b" PbootCMS" </password> kong_db_cache_miss" {\"acknowledged\":true}" webmaster level 2 username guest password guest" FileOutsidePaths loggedIn" \"absolutePath\":\"/var/logs/" token schema_name Fatal error" <title>Dashboard</title> create user ok!") Welcome to the Apache ActiveMQ Console of \"message\":\"An internal server error occurred\"" <?php \"\" {\"success\":\"true\", \"data\":{\"id\":1}, \"alert\":\"您正在使用默认密码登录，为保证设备安全，请立即修改密码\"}" <firmwareVersion> /_cat/master" top.location.href='(.*?)'; SolarWinds.Orion.Core.Common" right\">Router\\s*Admin\\s*Username< Method Not Allowed {\"error\":\"ElasticsearchParseException[Failed to derive xcontent from \"dept_name\":\" table_name resourceManagerVersionBuiltOn ServerRoot=* password 81dc9bdb52d04dc20036dbd8313ed05 Unauthorized Forticlient" gid <password> vRealize Operations Manager") cf79ae6addba60ad018347359bd144d2 con_db_name Ant-Version: db_name a29hbHIgaXMg%d2F0Y2hpbmcgeW9129" a29hbHIgaXMg%d2F0Y2hpbmcgeW9129 <title>NVMS-1000</title> pass=" Harbor Node-RED web server is listening" users di.php" left.php" Call to undefined function helper()" PrivilegeInfo phpMyAdmin Kafka Manager</a> downmix.inc.php" {\"data\":{\"users\":{\"edges\":[{\"node\":{\"username\":\" \"kubeletVersion\": \"v fgt_lang" PD9waH" delete user ok!") password" Cod::respond()") db_pwd <rootManagerPassword>" <title>Dubbo Admin</title> name resolve order 成功！") users" <TITLE>流媒体管理服务器</TITLE> null" kylin.metadata.url" /sysinfo/versions ef775988943825d2871e1cfa75473ec sql_error:MySQL Query Error" INTERNAL_PASSWORD_ENABLED {\"error\":\"ElasticsearchParseException[Failed to derive xcontent from" Method Not Allowed" root:[x*]?:0:0: Discuz! info</b>: MySQL Query Error /download/edr_installer_ {\"status\":\"invalid\",\"errors\": \"containerRuntimeVersion\"" \"id\":\"-7273032013234748168\" struts2_security_check" ^root:[x*]:0:0: {\"data\":\"0\",\"status\":1}" file_get_contents(" + string(r) + ")" \"uid\":" Services uid=0(admin) gid=0(admin) Free Physical Memory Size" DockerRootDir" device id: /application/third_party/CIUnit/libraries/CIUnitTestCase.php on line 反弹端口 : root', '/logout' : guest', '/logout' wheel_async user" DB_HOST" 6f7c6dcbc380aac3bcba1f9fccec991e" application/pdf" \"stormVersion\": custom_field1") 225773091 RegistryConfig /Orion/NetPerfMon/TemplateSiblingIconUrl") </password>" ((u|g)id|groups)=[0-9]{1,4}\\([a-z0-9]+\\) vendor\\laravel\\framework\\src\\Illuminate\\Routing\\RouteCollection.php") || respons DB_HOST java.version 401 - " <title>noVNC</title>" BIG-IP release hadoopVersion" stacktrace") || respons responseHeader H5_DEV jboss.management.local You Know, for Search" Welcome to H2" rootManagerName get_dkey_passwd Environment &amp; details repositories No such service [" + string(rand)) address dataexists <password>" ~" + string(r1) + "~") PbootCMS gitlist serverIdentifier" java.lang.NullPointerException:null") Cod::respond()" repositories" distributions application/pdf ncanal.aliyun.accessKey com.atlassian.confluence.setup.ConfluenceAppConfig for 16-bit app support \xff\xd8\xff\xe1 groupid data_auth_key This file is managed by man:systemd-resolved(8). Do not edit.") <object name=\"cm_md_db\">" account login success" phpmailer.php on line 10 \"result\":{\"success\":true} citrix <title>RG-UAC登录页面</title> <h2>Broker</h2>" 6f7c6dcbc380aac3bcba1f9fccec991e www.ifw8.cn" BIG-IP release" 当前已登录了一个用户，同一窗口中不能登录多个用户" proxies MethodNotAllowedHttpException Generic H2 groups ncanal.aliyun.secretKey" Directory of /" (root|toor):[x*]:0:0: \"message\":\"An internal server error occurred\"") .kibanaWelcomeView /seeyon/common/ password") left <%@ page session=\"false\" import=\"com.caucho.vfs.*, com.caucho.server.webapp.*\" %>") \"status\":true, replicator_manager" KernelVersion encrypted="""


def parse_post_data(request):
    try:
        if request.content_type is None:
            res = request.data
        elif request.content_type.startswith('application/xml'):
            res = request.data
        elif request.content_type.startswith('application/x-www'):
            res = request.get_data().decode()
        elif request.content_type.startswith('multipart/form-data'):
            res = request.form
        elif request.content_type.startswith('application/json'):
            res = request.data
        else:
            res = request.data
    except:
        res = ''
    return res


def transform_res2template(res):
    t = Template(res.text)
    return t


@app.route('/objects/<path:uri>', methods=['GET'])
def handle_youphptube_encoder_cve(uri):
    global DATA
    if len(request.full_path) > 40:
        return Template(apache_default + other_default).render(), 200
    else:
        return Template(DATA).render(), 200


@app.route('/cgi-bin/mainfunction.cgi', methods=['POST'])
def handle_cgi_bin():
    return Template('uid gid root:x:0:0:').render(), 200


@app.route('/plus/ajax_officebuilding.php', methods=['GET'])
def handle_74cms():
    value = request.args.get('key')
    if len(value) > 10:
        value = (value.split('md5(')[1].split('),')[0])
        value = hashlib.md5(value.encode('utf-8')).hexdigest()
        return Template(value).render(), 200
    else:
        return Template('not found').render(), 200


@app.route('/+CSCOT+/oem-customization', methods=['GET'])
def handle_CSCOT():
    return Template('INTERNAL_PASSWORD_ENABLED').render(), 200, {'Content-Type': 'application/octet-stream'}


@app.route('/pentaho/api/userrolelist/systemRoles', methods=['GET'])
def handle_pentaho():
    return Template('<roles>Anonymous</roles></roleList>').render(), 200, {"Set-Cookie": "JSESSIONID="}


@app.route('/admin/', methods=['GET'])
def handle_yccms_rce():
    try:
        a = request.args.get('a')
        if a[:4] == 'Fact':
            if '%2B' in a:
                return str(int(a.split('%2B')[0].split('print(')[1]) + int(a.split('%2B')[1].split(');')[0]))
            elif '%2b' in a:
                return str(int(a.split('%2b')[0].split('print(')[1]) + int(a.split('%2b')[1].split(');')[0]))
            else:
                return str(int(a.split('+')[0].split('print(')[1]) + int(a.split('+')[1].split(');')[0]))
        elif a[:4] == 'dopa':
            id = request.args.get('id')
            return str(int(id.split('*')[0].split('3,')[1]) * int(id.split('*')[1].split(',5')[0]))
        elif a[:4] == 'doSe':
            appno = request.args.get('appno')
            return str(int(appno.split('*')[0].split('ct+')[1]) * int(appno.split('*')[1].split(',9')[0]))
        else:
            headers = dict(zip(list(request.headers.keys()), list(request.headers.values())))
            R = REQ.get(url='http://127.0.0.1:9998' + request.full_path, headers=headers, allow_redirects=False)
            headers['Content-Type'] = R.headers['Content-Type'] if 'Content-Type' in list(
                R.headers.keys()) else 'text/plain; charset=utf-8'
            if R.status_code == 404:
                return Template(apache_default + other_default).render(), 200, headers
            else:
                t = transform_res2template(R)
                return t.render(), R.status_code, dict(R.headers)
    except:
        headers = dict(zip(list(request.headers.keys()), list(request.headers.values())))
        R = REQ.get(url='http://127.0.0.1:9998' + request.full_path, headers=headers, allow_redirects=False)
        headers['Content-Type'] = R.headers['Content-Type'] if 'Content-Type' in list(
            R.headers.keys()) else 'text/plain; charset=utf-8'
        if R.status_code == 404:
            return Template(apache_default + other_default).render(), 200, headers
        else:
            t = transform_res2template(R)
            return t.render(), R.status_code, dict(R.headers)


@app.route('/user/City_ajax.aspx', methods=['GET'])
def handle_city_ajax():
    try:
        city = request.args.get('CityId')
        value = city.split("'MD5','")[1].split("'))")[0]
        value = hashlib.md5(value.encode('utf-8')).hexdigest()
        return value
    except:
        return Template('not found').render(), 200


@app.route('/admin/cms_channel.php', methods=['GET'])
def handle_cms_channel():
    try:
        d = request.args.get('del')
        value = d.split('md5(')[1].split(')')[0]
        return hashlib.md5(value.encode('utf-8')).hexdigest()
    except:
        headers = dict(zip(list(request.headers.keys()), list(request.headers.values())))
        R = REQ.get(url='http://127.0.0.1:9998' + request.full_path, headers=headers, allow_redirects=False)
        headers['Content-Type'] = R.headers['Content-Type'] if 'Content-Type' in list(
            R.headers.keys()) else 'text/plain; charset=utf-8'
        if R.status_code == 404:
            return Template(apache_default + other_default).render(), 200, headers
        else:
            t = transform_res2template(R)
            return t.render(), R.status_code, dict(R.headers)


@app.route('/ping', methods=['GET'])
def handle_ping():
    return 'test', 204, {"x-influxdb-version": "x-influxdb-version"}


# @app.route('/a/<path:uri>', methods=['GET'])
# def handle_a_b(uri):
#     return Template('not found').render(), 200

@app.route('/icons/<path:uri>', methods=['GET'])
def handle_icons(uri):
    return Template('root:x:0:0:').render(), 200


@app.route('/run')
def run_proceess():
    return Template('salt/wheel/dd  wheel_async  runner_async').render(), 200, {'content-type': 'application/json'}


@app.route('/appmonitor/protected/selector/server_file/files', methods=['POST', 'GET'])
def process_appmonitor():
    return Template(
        "{\"name\":\"Windows\",\"path\":\"C:\\\\Windows\",\"folder\":true} {\"name\":\"root\",\"path\":\"/root\",\"folder\":true}").render(), 200, {
               'content-type': 'application/json'}


@app.route('/plus/download.php', methods=['GET'])
def handle_plus_download():
    return Template('not found').render(), 302, {"location": "https://www.du1x3r12345fds.com"}


@app.route('/menu/stapp', methods=['POST'])
def handle_citrix_8191():
    return Template('<script>alert({{r1}});</script> citrix').render(), 200


@app.route('/../../../../../../../../../../../../windows/win.ini', methods=['GET'])
def handle_more_dot():
    return Template('for 16-bit app support').render(), 200


@app.route('/api/v1/authentication/connection-token/', methods=['GET'])
def handle_api_v1():
    if request.full_path.find('user') != -1:
        return Template("\"\"").render(), 404, {'content-type': 'application/json'}
    else:
        return Template('not_authenticated').render(), 401, {'content-type': 'application/json'}


@app.route('/api/v1/users/connection-token/', methods=['GET'])
def handle_api_v2():
    if request.full_path.find('user-only') != -1:
        return Template("\"\"").render(), 404, {'content-type': 'application/json'}
    else:
        return Template('not_authenticated').render(), 401, {'content-type': 'application/json'}


@app.route('/password_change.cgi', methods=['POST'])
def handle_passwd_cgi():
    data = parse_post_data(request).decode()
    tmp = int(data.split('%20%2b%20')[0].split('expr%20')[1]) + int(data.split('%20%2b%20')[1].split('&ne')[0])
    return Template(str(tmp)).render(), 200


@app.route("/c6/Jhsoft.Web.login/AjaxForLogin.aspx", methods=["GET", "POST"])
def poc_yaml_weblogic_cve_oa_c66():
    try:
        if request.method == 'POST':
            res = "\xcf\xb5\xcd\xb3\xb9\xdc\xc0\xed\xd4\xb1\x7c  \xc4\xfa\xba\xc3\x7c\x7c\x7c"
            print('cve_2018_17246 succeed')
    except:
        res = 'hello world'
    return res, 200, [("Set-Cookie", "SessionIDAdmin=")]


# 17:52
@app.route("/s/opentsdb_header.jpg", methods=["GET", "POST"])
def poc_yaml_weblogic_cve_2020_35476():
    try:
        if request.method == 'GET':
            res = "text/plain \xff\xd8\xff\xe1"
            print('poc_yaml_2020-35476 succeed')
    except:
        res = 'hello world'
    return res


@app.route("/api/ping", methods=["GET", "POST"])
def poc_yaml_weblogic_cve_iptv_rce():
    try:
        if request.method == 'GET':
            m = request.values.get("host")
            r1 = int(re.findall(":(\d*):", m)[0])
            r2 = int(re.findall("(\d*)\)", m)[0])
            res = str(r1 + r2)
            print('poc_yaml_weblogic_cve_iptv_rce succeed')
    except:
        res = 'hello world'
    return res


# 刚去掉，可能需要加上
# @app.route("/<re(r'[a-z]{6}\.txt'):mobile>",methods=["GET", "POST","PUT"])
# def poc_yaml_weblogic_put_getshell(mobile):
#     try:
#         if request.method == 'PUT':
#             global fileContent
#             if request.content_type.startswith('application/json'):
#                 # comment = request.get_json()["content"]
#                 fileContent = request.json.get('content')
#             elif request.content_type.startswith('multipart/form-data'):
#                 fileContent = request.form.get('content')
#             else:
#                 fileContent = request.values.get("content")

#             print('cve_2018_17246 succeed')
#             return "data root", 201
#         elif request.method == 'GET':
#             return fileContent
#     except:
#         res = 'hello world'
#         pass
#     return "11111",200,[("Set-Cookie", "SessionIDAdmin=")]


# 17:12
# @app.route("/node",methods=["GET", "POST","PUT"])
# def poc_yaml_weblogic_2019_6340():
#     try:
#         if request.method == 'POST':
#             if request.content_type.startswith('application/json'):
#                 fileContent = request.json.get('options')
#             elif request.content_type.startswith('multipart/form-data'):
#                 fileContent = request.form.get('options')
#             else:
#                 fileContent = request.values.get("options")
#             print('poc_yaml_weblogic_2019_6340 succeed')
#             print("fileContent",fileContent)
#             r2 = re.findall("\%\%([a-z]{4})", fileContent)[0]
#             r1 = re.findall("([a-z]{4})\%\%", fileContent)[0]
#             return r1+"%"+r2,200
#         elif request.method == 'GET':
#             return fileContent
#     except:
#         res = 'hello world'
#         pass
#     return "11111",200,[("Set-Cookie", "SessionIDAdmin=")]


# #16:44
# @app.route("/api/ping", methods=["GET", "POST"])
# def poc_yaml_weblogic_cve_iptv_rce():
#     try:
#         if request.method == 'GET':
#             m = request.values.get("host")
#             r1 = int(re.findall(":(\d*):",m)[0])
#             r2 = int(re.findall("(\d*)\)",m)[0])
#             res = str(r1+r2)
#             print('poc_yaml_weblogic_cve_iptv_rce succeed')
#     except:
#         res = 'hello world'
#     return res


# @app.route("/<re(r'\d{8}\.php'):mobile>",methods=["GET", "POST","PUT"])
# def poc_yaml_weblogic_8php(mobile):
#     try:
#         if request.method == 'GET':
#             return "data root", 201
#     except:
#         # res = 'hello world'
#         pass
#     return "11111",200


# @app.route("/get_luser_by_sshport.php",methods=["GET", "POST","PUT"])
# def poc_yaml_weblogic_1php():
#     try:
#         if request.method == 'GET':
#             return "data root", 200
#     except:
#         pass
#     return "11111",200


# @app.route("/<re(r'[a-z]{10}\.php'):mobile>",methods=["GET", "POST","PUT"])
# def poc_yaml_weblogic_10php(mobile):
#     try:
#         if request.method == 'GET':
#             print(mobile[:-4])
#             mobile = mobile[:-4].encode("utf-8")
#             res = hashlib.md5(mobile).digest()
#             return res, 200
#     except:
#         # res = 'hello world'
#         pass
#     return "11111",200


# 处理特殊情况
@app.route('/favicon.ico', methods=['GET'])
def handle_ico():
    return ''


# 处理GET请求
@app.route('/<path:uri>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy2yarx(uri=0):
    headers = dict(zip(list(request.headers.keys()), list(request.headers.values())))
    # # 特别处理
    if request.full_path == '/?q=node&destination=node':
        return Template('e2fc714c4727ee9395f324cd2e7f331f 587c39e2b2a68be44d8e91e1a1a59c1b').render(), 500

    if request.method == 'POST':
        data = parse_post_data(request)
        R = REQ.post(url='http://127.0.0.1:9998' + request.full_path, headers=headers, data=data,
                     allow_redirects=False)
    elif request.method == 'PUT':
        data = parse_post_data(request)
        R = REQ.put(url='http://127.0.0.1:9998' + request.full_path, headers=headers, data=data,
                    allow_redirects=False)
    elif request.method == 'DELETE':
        R = REQ.delete(url='http://127.0.0.1:9998' + request.full_path, headers=headers)
    else:
        R = REQ.get(url='http://127.0.0.1:9998' + request.full_path, headers=headers, allow_redirects=False)
    # 目前下面的用不到，因为返回的就是yarx响应头
    headers['Content-Type'] = R.headers['Content-Type'] if 'Content-Type' in list(
        R.headers.keys()) else 'text/plain; charset=utf-8'
    if R.status_code == 404:
        return Template(apache_default + other_default).render(), 200, headers
    else:
        t = transform_res2template(R)
        return t.render(), R.status_code, dict(R.headers)


# 处理访问根路由，根路由访问就不转发了，目前全部返回空字符串
@app.route('/', methods=['GET', 'PUT', 'DELETE'])
def index():
    if len(request.full_path) > 2 and request.method == 'GET':
        headers = dict(zip(list(request.headers.keys()), list(request.headers.values())))
        R = REQ.get(url='http://127.0.0.1:9998' + request.full_path, headers=headers, allow_redirects=False)
        if R.status_code == 404:
            return Template(apache_default + other_default).render(), 200, headers
        else:
            return transform_res2template(R).render(), R.status_code, dict(R.headers)
    else:
        t = Template(apache_default)
        return t.render()


@app.route('/', methods=['POST'])
def index_post():
    data = parse_post_data(request)
    try:
        data = data.decode()
    except:
        pass
    if 'username' in data:
        return Template('not found').render(), 302, {"location": "/page/login/login_fail.html"}
    elif 'routestring' in data:
        value = data.split('md5(')[1].split('))')[0]
        value = hashlib.md5(value.encode('utf-8')).hexdigest()
        return Template(value).render(), 200
    else:
        return Template(apache_default + other_default).render(), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9999, debug=True)

from flask import Flask, request, redirect, url_for, flash, render_template_string
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess
import os
import json
import signal
import atexit

app = Flask(__name__)
app.secret_key = b'}N\xf5\t\x10\x08W\xf6W>\x93d\x18\xbc\xca\xb3\x10\xf5\xd1\x8d\x98>\x1aa'  # 你的密钥

# 初始化认证
auth = HTTPBasicAuth()

# 设置用户名和密码
users = {
    "xierlove": generate_password_hash("xierlove")  # 用户名: xierlove, 密码: xierlove
}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

# 定义规则存储文件路径
RULES_FILE = '/opt/gost_web/rules.json'

# 定义 GOST 子进程
gost_process = None

# HTML 模板包含在 Python 字符串中
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>XIERCLOUD转发</title>
    <style>
    body {
        font-family: Arial, sans-serif;
        background-color: #f4f4f4;
    }

    .container {
        width: 700px;
        margin: 50px auto;
        padding: 30px;
        background: #fff;
        border-radius: 8px;
        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
    }

    h1 {
        text-align: center;
        margin-bottom: 20px;
    }

    form label {
        display: block;
        margin-top: 10px;
    }

    form input, form select {
        width: 100%;
        padding: 8px;
        margin-top: 5px;
        box-sizing: border-box;
    }

    button {
        margin-top: 20px;
        padding: 10px 20px;
        background: #28a745;
        border: none;
        color: #fff;
        font-size: 16px;
        cursor: pointer;
    }

    button:hover {
        background: #218838;
    }

    .alert {
        padding: 10px;
        margin-bottom: 15px;
        border-radius: 4px;
    }

    .alert.success {
        background-color: #d4edda;
        color: #155724;
    }

    .alert.danger {
        background-color: #f8d7da;
        color: #721c24;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 30px;
    }

    table, th, td {
        border: 1px solid #ddd;
    }

    th, td {
        padding: 12px;
        text-align: left;
    }

    th {
        background-color: #f2f2f2;
    }

    .delete-button {
        background-color: #dc3545;
        color: white;
        border: none;
        padding: 5px 10px;
        cursor: pointer;
        border-radius: 4px;
    }

    .delete-button:hover {
        background-color: #c82333;
    }
    </style>
</head>
<body>
    <div class="container">
        <h1>XIERCLOUD转发</h1>
        <p>当前操作系统：{{ os_type }}</p>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert {{ category }}">
                {{ message }}
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <h2>创建新的转发规则</h2>
        <form method="POST">
            <label for="protocol">协议:</label>
            <select id="protocol" name="protocol" required>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
            </select>

            <label for="local_addr">本地地址:</label>
            <input type="text" id="local_addr" name="local_addr" value="127.0.0.1" required>

            <label for="local_port">本地端口:</label>
            <input type="number" id="local_port" name="local_port" value="8080" required>

            <label for="remote_addr">远程地址:</label>
            <input type="text" id="remote_addr" name="remote_addr" value="example.com" required>

            <label for="remote_port">远程端口:</label>
            <input type="number" id="remote_port" name="remote_port" value="80" required>

            <button type="submit">添加规则</button>
        </form>

        <h2>现有转发规则</h2>
        {% if rules %}
        <table>
            <tr>
                <th>ID</th>
                <th>协议</th>
                <th>本地地址:端口</th>
                <th>远程地址:端口</th>
                <th>操作</th>
            </tr>
            {% for rule in rules %}
            <tr>
                <td>{{ loop.index }}</td>
                <td>{{ rule.protocol.upper() }}</td>
                <td>{{ rule.local_addr }}:{{ rule.local_port }}</td>
                <td>{{ rule.remote_addr }}:{{ rule.remote_port }}</td>
                <td>
                    <form method="POST" action="{{ url_for('delete_rule', rule_id=loop.index0) }}">
                        <button type="submit" class="delete-button">删除</button>
                    </form>
                </td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>暂无转发规则。</p>
        {% endif %}
    </div>
</body>
</html>
"""

def detect_os():
    """
    检测当前操作系统类型。
    """
    try:
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release') as f:
                lines = f.readlines()
            os_info = {}
            for line in lines:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    os_info[key] = value.strip('"')
            if 'ID' in os_info:
                return os_info['ID']
    except Exception as e:
        print(f"检测操作系统时出错: {e}")
    return 'unknown'

def load_rules():
    """
    从 JSON 文件加载规则。
    """
    if not os.path.exists(RULES_FILE):
        return []
    with open(RULES_FILE, 'r') as f:
        try:
            rules = json.load(f)
            return rules
        except json.JSONDecodeError:
            return []

def save_rules(rules):
    """
    将规则保存到 JSON 文件。
    """
    with open(RULES_FILE, 'w') as f:
        json.dump(rules, f, indent=4)

def start_gost(rules):
    """
    启动 GOST 作为子进程，根据当前规则。
    """
    global gost_process
    if gost_process and gost_process.poll() is None:
        gost_process.terminate()
        gost_process.wait()

    if not rules:
        return

    try:
        gost_path = '/usr/local/bin/gost/gost'  # 根据实际安装路径调整
        cmd = [gost_path]
        for rule in rules:
            cmd.extend(['-L', f"{rule['protocol']}://{rule['local_addr']}:{rule['local_port']}"])
            cmd.extend(['-F', f"{rule['protocol']}://{rule['remote_addr']}:{rule['remote_port']}"])

        gost_process = subprocess.Popen(cmd)
        print("GOST 服务已启动。")
    except Exception as e:
        print(f"启动 GOST 时出错: {e}")
        gost_process = None

def update_gost_service(rules):
    """
    更新 GOST 服务，根据当前规则。
    """
    start_gost(rules)

@app.route('/', methods=['GET', 'POST'])
@auth.login_required
def index():
    os_type = detect_os()
    rules = load_rules()

    if request.method == 'POST':
        # 获取表单数据
        protocol = request.form.get('protocol', 'tcp').lower()
        local_addr = request.form.get('local_addr', '127.0.0.1').strip()
        local_port = request.form.get('local_port', '8080').strip()
        remote_addr = request.form.get('remote_addr', 'example.com').strip()
        remote_port = request.form.get('remote_port', '80').strip()

        # 简单验证
        if not (protocol and local_addr and local_port and remote_addr and remote_port):
            flash('所有字段都是必填的。', 'danger')
            return redirect(url_for('index'))

        # 验证端口是否为数字
        if not (local_port.isdigit() and remote_port.isdigit()):
            flash('端口必须是数字。', 'danger')
            return redirect(url_for('index'))

        # 添加新规则
        new_rule = {
            'protocol': protocol,
            'local_addr': local_addr,
            'local_port': local_port,
            'remote_addr': remote_addr,
            'remote_port': remote_port
        }
        rules.append(new_rule)
        save_rules(rules)
        update_gost_service(rules)
        flash('规则添加成功！', 'success')
        return redirect(url_for('index'))

    # 渲染内嵌的 HTML 模板
    return render_template_string(HTML_TEMPLATE, os_type=os_type, rules=rules)

@app.route('/delete/<int:rule_id>', methods=['POST'])
@auth.login_required
def delete_rule(rule_id):
    rules = load_rules()
    if 0 <= rule_id < len(rules):
        removed_rule = rules.pop(rule_id)
        save_rules(rules)
        update_gost_service(rules)
        flash('规则删除成功！', 'success')
    else:
        flash('无效的规则 ID。', 'danger')
    return redirect(url_for('index'))

def shutdown_gost():
    """
    在应用关闭时终止 GOST 子进程。
    """
    global gost_process
    if gost_process and gost_process.poll() is None:
        gost_process.terminate()
        gost_process.wait()
        print("GOST 服务已停止。")

atexit.register(shutdown_gost)

if __name__ == '__main__':
    # 在容器启动时加载并启动 GOST
    rules = load_rules()
    update_gost_service(rules)

    # 启动 Flask 应用
    app.run(host='0.0.0.0', port=5000)

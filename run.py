from flask import Flask, render_template, request, redirect, url_for, flash, g
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
from flask import session


app = Flask(__name__)

bcrypt = Bcrypt(app)

app.secret_key = 'mysecretkey'


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/')
def portada():
    return render_template('portada.html')


@app.route('/registro')
def registro():
    return render_template('registro.html')


@app.route('/autenticacion')
def autenticacion():
    return render_template('autenticacion.html')


@app.route('/scannertools')
def index():
    if not g.user:
        return render_template('restriccion.html')
    else:
        nombre = g.user

        return render_template('index.html', nombre=nombre)


@app.route('/actividad')
def actividad():
    if not g.user:
        return render_template('restriccion.html')
    else:
        nombre = g.user
        cur = sqlite3.connect("base_datos.db")
        cursor = cur.cursor()
        cursor.execute("SELECT * FROM escaneo")
        records = cursor.fetchmany(1000)
        cursor.close()
        return render_template('actividad.html', nombre=nombre, contacts=records)


@app.route('/restriccion')
def restriccion():
    return render_template('restriccion.html')


@app.route('/dispositivos')
def dispositivos():
    if not g.user:
        return render_template('restriccion.html')

    else:
        nombre = g.user
        return render_template('dispositivos.html', nombre=nombre)


@app.route('/puertos')
def puertos():
    if not g.user:
        return render_template('restriccion.html')
    else:
        nombre = g.user
        return render_template('puertos.html', nombre=nombre)


@app.route('/sistema_operativo')
def sistema_operativo():
    if not g.user:
        return render_template('restriccion.html')

    else:
        nombre = g.user
        return render_template('sistema_operativo.html', nombre=nombre)


# ---------------------*------------------------*----------------------*-----------

# Registro de usuarios

@app.route('/envio_registro', methods=['GET', 'POST'])
def envio_registro():

    if request.method == 'POST':

        nombre = request.form['nombre']
        apellido = request.form['apellido']
        correo = request.form['correo']
        contraseña = bcrypt.generate_password_hash(
            request.form['contraseña']).decode('utf-8')

        import sqlite3
        from sqlite3 import Error
        from flask_bcrypt import Bcrypt

        try:

            con = sqlite3.connect('base_datos.db')
            cursor = con.cursor()
            cursor.execute(f' SELECT * FROM usuario where correo = "{correo}"')
            rv = cursor.fetchone()
            if rv:
                flash("Correo vinculada con otra cuenta")
                con.commit()
                return render_template('registro.html')
            else:

                cursor.execute("INSERT INTO usuario (nombre, apellido, correo, contraseña) VALUES (?, ?, ?, ?)", (
                    nombre, apellido, correo, contraseña))
                con.commit()

                try:

                    import smtplib
                    from email.mime.multipart import MIMEMultipart
                    from email.mime.text import MIMEText

                    me = "scannertoolsutt@gmail.com"
                    you = correo
                    msg = MIMEMultipart('alternative')
                    msg['Subject'] = f"Bienvenido a nuestra comunidad {nombre}"
                    msg['From'] = me
                    msg['To'] = you
                    text = ""
                    html = """\
                    <html>
                    
                    <head>
                    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
                        
                    <title>ScannerTools</title>
                    <style type="text/css">
                        a {color: #d80a3e;}
                    body, #header h1, #header h2, p {margin: 0; padding: 0;}
                    #main {border: 1px solid #cfcece;}
                    img {display: block;}
                    #top-message p, #bottom p {color: #3f4042; font-size: 12px; font-family: Arial, Helvetica, sans-serif; }
                    #header h1 {color: #ffffff !important; font-family: "Lucida Grande", sans-serif; font-size: 24px; margin-bottom: 0!important; padding-bottom: 0; }
                    #header p {color: #ffffff !important; font-family: "Lucida Grande", "Lucida Sans", "Lucida Sans Unicode", sans-serif; font-size: 12px;  }
                    h5 {margin: 0 0 0.8em 0;}
                        h5 {font-size: 18px; color: #ffffff !important; font-family: Arial, Helvetica, sans-serif; }
                    p {font-size: 12px; color: #000000 !important; font-family: "Lucida Grande", "Lucida Sans", "Lucida Sans Unicode", sans-serif; line-height: 1.5;}
                    .w {font-size: 12px; color: #ffffff !important; font-family: "Lucida Grande", "Lucida Sans", "Lucida Sans Unicode", sans-serif; line-height: 1.5;}
                    </style>
                    </head>
                    
                    <body  bgcolor="3b3c45">
                    
                    
                    <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#ffffff"><tr><td>
                    <table id="top-message" cellpadding="20" cellspacing="0" width="600" align="center">
                        <tr>
                        <td align="center">
                            
                        </td>
                        </tr>
                    </table>
                    
                    <table id="main" width="600" align="center" cellpadding="0" cellspacing="15" bgcolor="3b3c45">
                        <tr>
                        <td>
                            <table id="header" cellpadding="10" cellspacing="0" align="center" bgcolor="8fb3e9">
                            <tr>
                                <td width="570" align="center"  bgcolor="#3b3c45"><h1>Scanner Tools</h1></td>
                            </tr>
                            <tr>
                                <td width="570" align="center" bgcolor="#3b3c45"><p>Vulnerabilidades en tu red</td>
                            </tr>
                            </table>
                        </td>
                        </tr>
                    
                        <tr>
                        <td>
                            <table id="content-3" cellpadding="0" cellspacing="0" align="center">
                            <tr>
                                <td width="15"></td>
                                <td width="250" valign="top" bgcolor="3b3c45" style="padding:5px;">
                                    <img src="https://i.ibb.co/hMfRbzs/portada.png" width ="250" height="150" />
                                </td>
                            </tr>
                            </table>
                        </td>
                        </tr>
                        <tr>
                        <td>
                            <table id="content-4" cellpadding="0" cellspacing="0" align="center">
                            <tr>
                                <td width="15"></td>
                                <td width="200" valign="top">
                                <h5>Bienvenido a Scanner Tools</h5>
                                <p class="w">Gracias por formar parte de nuestra comunidad. Los reportes de escaner se enviaran a este correo electronico. Disfruta de nuestro sitio.</p>
                                </td>
                            </tr>
                            </table>
                        </td>
                        </tr>
                        
                    
                    </table>

                    <table id="bottom" cellpadding="20" cellspacing="0" width="600" align="center">
                        <tr>
                        <td align="center">
                            <p>Tecnologias de la Información y Comunicación Infraestructura de Redes Digitales</p>
                            
                        </td>
                        </tr>
                    </table>
                    </table>

                    
                    </body>
                    </html>
                    """
                    part1 = MIMEText(text, 'plain')
                    part2 = MIMEText(html, 'html')
                    msg.attach(part1)
                    msg.attach(part2)
                    mail = smtplib.SMTP('smtp.gmail.com', 587)
                    mail.ehlo()
                    mail.starttls()
                    mail.login('scannertoolsutt@gmail.com', 'AsDfGhJk')
                    mail.sendmail(me, you, msg.as_string())
                    mail.quit()
                    f = "Usuario registrado"
                    return render_template('autenticacion.html', f=f)

                except:

                    f = "No se encontro el correo"
                    return render_template('autenticacion.html', f=f)

        except Error:

            flash(Error)


# ---------------------*------------------------*----------------------*-----------

# Inicio de sesión


@app.route('/login', methods=['GET', 'POST'])
def login():

    import sqlite3
    from sqlite3 import Error
    from flask_bcrypt import Bcrypt

    error = None

    if request.method == 'POST':
        session.pop('user', None)

        session['user'] = request.form['correo']
        contraseña = request.form['contraseña']
        try:

            with sqlite3.connect("base_datos.db") as con:
                cur = con.cursor()

                user = session['user']
                cur.execute(f'SELECT * FROM usuario where correo = "{user}"')

                rv = cur.fetchone()
                i = 0

                while i<3:
                    if rv:
                        if bcrypt.check_password_hash(rv[4], contraseña):

                            session['user'] = rv[3]
                            return redirect(url_for('index'))
                        else:
                            flash(f'{rv[1]}, su contraseña es incorrecta.')
                            error = "Recuperar cuenta."
                            return render_template('autenticacion.html', error=error)

                    else:
                        flash('Usuario invalido')
                        return redirect(url_for('autenticacion'))
                

        except Error:
            flash("Error con base de datos")

# ---------------------*------------------------*----------------------*-----------

# cerrar sesion


@app.route('/salir')
def salir():
    session.pop('user', None)
    flash('Cerro sesión')
    return redirect(url_for('autenticacion'))


# ---------------------*------------------------*----------------------*-----------

# Protejer sitios

@app.route('/protegido')
def protegido():
    if g.user:
        return render_template('index.html')
    return redirect(url_for('autenticacion'))


# --- ---- ------ ------ ------- ------- -------- --------- -------- -------- -------

# Iniciar session

@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']

# ---------------------*------------------------*----------------------*-----------

# Escaneo


@app.route('/escaneo_equipo', methods=['POST'])
def escaneo_equipo():

    if request.method == 'POST':

        import socket

        nombre_equipo = socket.gethostname()
        direccion_equipo = socket.gethostbyname(nombre_equipo)
        nombre = "El nombre del equipo es: %s" % nombre_equipo
        direccion = "La IP es: %s" % direccion_equipo
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        salida = s.getsockname()[0]
        ip = "Ip de salida de internet: %s" % salida
        s.close()
        flash(nombre)
        flash(direccion)
        flash(ip)
        return redirect(url_for('index'))


@app.route('/escaneo_dipositivos', methods=['POST'])
def escaneo_dispositivos():

    if request.method == 'POST':

        import nmap
        import time
        from datetime import date, datetime
        
        correo = g.user
        hora = time.strftime("%I:%M:%S")
        fecha = date.today()

        rango = request.form['rango']
        nombre_escaneo = "Escaneo de dispositivos"

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=rango, arguments='-sn -sP')
            direccion = [(x, nm[x]['vendor']) for x in nm.all_hosts()]
            e = []
            for direc in direccion:
                e.append(direc)
                flash(direc)

            z = e
            try:
                con = sqlite3.connect('base_datos.db')
                cursor = con.cursor()
                cursor.execute("INSERT INTO escaneo (nombre_escaneo, escaneo, correo, hora, fecha) VALUES (?, ?, ?, ?, ?)", (nombre_escaneo, str(z), correo, hora, fecha))
                con.commit()
                return redirect(url_for('dispositivos'))
            except:
                return redirect(url_for('dispositivos'))

        except:
            flash("No se pudo realizar el escaneo, intente de nuevo")
            return redirect(url_for('dispositivos'))

@app.route('/escaneo_puertos', methods=['GET', 'POST'])
def escaneo_puertos():

    if request.method == 'POST':
        import time
        from datetime import date, datetime

        hora = time.strftime("%I:%M:%S")
        fecha = date.today()

        select = request.form['select']
        rango = request.form['rango']
        correo = g.user

        if select == '1':
            import nmap
            import sys
            import socket

            cant_puertos = "1-1000"

            es = nmap.PortScanner()

            es.scan(rango, cant_puertos)

            try:
                e = []

                for host in es.all_hosts():
                    a = 'Host : %s (%s)' % (host, es[host].hostname())
                    b = 'State : %s' % es[host].state()

                for proto in es[host].all_protocols():
                    c = 'Protocol : %s' % proto

                    lport = es[host][proto].keys()
                    for port in lport:
                        e.append('..Puerto : %s \ Estado : %s..' %
                                 (port, es[host][proto][port]['state']))
                    flash(a)
                    flash(b)
                    flash(c)
                    flash(e)

                    z = a, b, c, e

                    nombre_escaneo = "Puertos disponibles"

                    try:
                        con = sqlite3.connect('base_datos.db')
                        cursor = con.cursor()
                        cursor.execute("INSERT INTO escaneo (nombre_escaneo, escaneo, correo, hora, fecha) VALUES (?, ?, ?, ?, ?)", (nombre_escaneo, str(z), correo, hora, fecha))
                        con.commit()
                        return render_template("puertos.html", nombre=correo)
                    except:
                        return render_template("puertos.html", nombre=correo)

            except:
                flash("La dirección ip no se encuentra activa en la red")
                return render_template("puertos.html", nombre=correo)

        elif select == "2":

            import nmap

            nm = nmap.PortScanner()

            try:
                nm.scan(rango, '1-6000')
                nm[rango].state()
                nm[rango].all_protocols()
                nm.all_hosts()
                nm[rango]['tcp'].keys()

                c = []

                if nm.scan():
                    for host in nm.all_hosts():
                        a = 'Estado : %s' % nm[host].state()

                        for proto in nm[host].all_protocols():
                            b = 'Protocolo : %s' % proto

                            lport = nm[host][proto].keys()
                            for port in lport:
                                c.append('*  Puerto : %s Estado : %s  *' %
                                         (port, nm[host][proto][port]['state']))

                            flash(f"Escaneo completo de la IP {rango}")
                            flash(a)
                            flash(b)
                            flash(c)

                            z = a, b, c
                            nombre_escaneo = "Puertos TCP"

                            try:
                                con = sqlite3.connect('base_datos.db')
                                cursor = con.cursor()

                                cursor.execute("INSERT INTO escaneo (nombre_escaneo, escaneo, correo, hora, fecha) VALUES (?, ?, ?, ?, ?)", (
                                    nombre_escaneo, str(z), correo, hora, fecha))

                                con.commit()
                                return render_template("puertos.html", nombre=correo)
                            except:
                                return render_template("puertos.html", nombre=correo)

                else:
                    flash("LO LAMENTAMOS")
                    flash("No hay puertos TCP disponibles")
                    return render_template("puertos.html", nombre=correo)
            except:
                flash("La dirección ip no se encuentra activa en la red")
                return render_template("puertos.html", nombre=correo)

        elif select == "3":

            import nmap

            nm = nmap.PortScanner()
            ip = '192.168.1.254'

            try:
                nm.scan(ip, '1-1024')
                c = []

                if nm.scan():

                    nm.scan(ip, '1-1024', '-v -sU')
                    a = "Estado: ", nm[ip].state()
                    b = "Protocolo", nm[ip].all_protocols()

                    for x in nm[ip]['udp'].keys():

                        c = "Puertos abiertos: ", x

                    flash(f"Escaneo completo de la IP {rango}")
                    flash(a)
                    flash(b)
                    flash(c)
                    nombre_escaneo = "Puertos UDP"
                    z = a, b, c

                    try:
                        con = sqlite3.connect('base_datos.db')
                        cursor = con.cursor()

                        cursor.execute("INSERT INTO escaneo (nombre_escaneo, escaneo, correo, hora, fecha) VALUES (?, ?, ?, ?, ?)", (
                            nombre_escaneo, str(z), correo, hora, fecha))

                        con.commit()
                        return render_template("puertos.html", nombre=correo)
                    except:
                        return render_template("puertos.html", nombre=correo)

                else:
                    flash("LO LAMENTAMOS")
                    flash("No hay puertos UDP disponibles")
                    return render_template("puertos.html", nombre=correo)

            except:
                flash("La dirección ip no se encuentra activa en la red")
                return render_template("puertos.html", nombre=correo)
        else:
            flash("Selecciona el tipo de puerto a escanear")
            return render_template("puertos.html", nombre=correo)

@app.route('/escaneo_sistema', methods=['POST'])
def escaneo_sistema():

    if request.method == 'POST':
        nombre = g.user
        rango = request.form['rango']

        import nmap

        try:
            nm = nmap.PortScanner()
            maquina = nm.scan(rango, arguments='-O')

            b = maquina['scan'][rango]['osmatch'][0]['osclass'][0]['osfamily']
            if b == "Linux":
                linux = f"El sistema operativo de la direccion {rango} es: {b}  "
                return render_template('sistema_operativo.html', nombre=nombre, linux=linux)
            elif b == "Windows":
                windows = f"El sistema operativo de la direccion {rango} es: {b}  "
                return render_template('sistema_operativo.html', nombre=nombre, windows=windows)
            else:
                otro = f"El sistema operativo de la direccion {rango} es: {b}  "
                return render_template('sistema_operativo.html', nombre=nombre, otro=otro)
        except:
            flash("Dirección fuera de rango.")
            return redirect(url_for('sistema_operativo'))

@app.route('/busqueda', methods=['POST'])
def busqueda():

    if request.method == 'POST':

        q = request.form['buscar']
        from googlesearch import search
        import webbrowser

        tld = "com"
        lang = "en"
        num = 100
        start = 0
        stop = num
        pause = 2.0
        results = search(q, tld=tld, lang=lang, num=num,
                         start=start, stop=stop, pause=pause)
        for r in results:
            webbrowser.open(r, new=2, autoraise=True)
            break
        return redirect(url_for('index'))

# --- ---- ------ ------ ------- ------- -------- --------- -------- -------- -------

# Eliminar datos

@app.route('/delete/<string:id>')
def delete_contact(id):

    cur = sqlite3.connect("base_datos.db")
    cursor = cur.cursor()
    cursor.execute('DELETE FROM escaneo WHERE Id = {0}' .format(id))
    cur.commit()
    return redirect(url_for('actividad'))

# --- ---- ------ ------ ------- ------- -------- --------- -------- -------- -------

#  Envio de reporte

@app.route('/envio_reporte/<string:id>')
def envio_reporte(id):
    if not g.user:
        return render_template('restriccion.html')
    else:
        try:
            cur = sqlite3.connect("base_datos.db")
            cursor = cur.cursor()
            cursor.execute('SELECT * FROM escaneo WHERE Id = {0}' .format(id))
            records = cursor.fetchmany(1000)
            usuario = {
                'nombre' : records[0:1:1]
                }
            cur.commit()

            try:
                import smtplib
                from email.mime.multipart import MIMEMultipart
                from email.mime.text import MIMEText

                me = "scannertoolsutt@gmail.com"
                you = g.user
                msg = MIMEMultipart('alternative')
                msg['Subject'] = "Reporte de actividad."
                msg['From'] = me
                msg['To'] = you
                text = ""
                html = f"""

                <html>
                
                <head>
                <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
                    
                <title>ScannerTools-Reporte de actividad</title>

                </head>
                
                <body  bgcolor="#ffffff">
                
                
                <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#3b3c45"><tr><td>
                <table id="top-message" cellpadding="20" cellspacing="0" width="600" align="center">
                    <tr>
                    <td align="center">
                        
                    </td>
                    </tr>
                </table>
                
                <table id="main" width="600" align="center" cellpadding="0" cellspacing="15" bgcolor="3b3c45">
                    <tr>
                    <td>
                        <table id="header" cellpadding="10" cellspacing="0" align="center" bgcolor="8fb3e9">
                        <tr>
                            <td width="570" align="center"  bgcolor="#3b3c45"><h1 style="color:#ffffff">Scanner Tools</h1></td>
                        </tr>
                        <tr>
                            <td width="570" align="center" bgcolor="#3b3c45"><p style="color:#ffffff">Vulnerabilidades en tu red</td>
                        </tr>
                        </table>
                    </td>
                    </tr>
                
                    <tr>
                    <td>
                        <table id="content-3" cellpadding="0" cellspacing="0" align="center">
                        <tr>
                            <td width="15"></td>
                            <td width="250" valign="top" bgcolor="3b3c45" style="padding:5px;">
                                <img src="https://i.ibb.co/hMfRbzs/portada.png" width ="250" height="150" />
                            </td>
                        </tr>
                        </table>
                    </td>
                    </tr>
                    <tr>
                    <td>
                        <table id="content-4" cellpadding="0" cellspacing="0" align="center">
                        <tr>
                            <td width="15"></td>
                            <td width="200" valign="top">
                            <h5 style="color:#ffffff">Reporte de escaneo.</h5>
                            <p class="w" style="color:#ffffff">{usuario['nombre']}</p>
                            </td>
                        </tr>
                        </table>
                    </td>
                    </tr>
                    
                
                </table>

                <table id="bottom" cellpadding="20" cellspacing="0" width="600" align="center">
                    <tr>
                    <td align="center">
                        <p style="color:#ffffff">Tecnologias de la Informacion y Comunicacion Infraestructura de Redes Digitales</p>
                        
                    </td>
                    </tr>
                </table>


                
                </body>
                </html>
                    

                """
                part2 = MIMEText(html, 'html')
                msg.attach(part2)
                mail = smtplib.SMTP('smtp.gmail.com', 587)
                mail.ehlo()
                mail.starttls()
                mail.login('scannertoolsutt@gmail.com', 'AsDfGhJk')
                mail.sendmail(me, you, msg.as_string())
                mail.quit()

                flash("El reporte se envio a su correo.")
                return redirect(url_for('actividad'))

            except:
                flash("Ocurrio un error, intentelo nuevamente.")
                return redirect(url_for('actividad'))

        except:

            flash("Ocurrio un error, intentelo de nuevo.")
            return redirect(url_for('actividad'))

@app.route('/recuperar_cuenta',methods=['GET', 'POST'])
def recuperar_cuenta():
    from random import choice
    
    longitud = 10
    valores = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ<=>@#%&+"

    contraseña = ""
    contraseña = contraseña.join([choice(valores) for i in range(longitud)])
    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        me = "scannertoolsutt@gmail.com"
        you = g.user
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Recuperar cuenta."
        msg['From'] = me
        msg['To'] = you
        text = ""
        html = f"""

                <html>
                
                <head>
                <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
                    
                <title>ScannerTools-Recuperar cuenta</title>

                </head>
                
                <body  bgcolor="#ffffff">
                
                
                <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#3b3c45"><tr><td>
                <table id="top-message" cellpadding="20" cellspacing="0" width="600" align="center">
                    <tr>
                    <td align="center">
                        
                    </td>
                    </tr>
                </table>
                
                <table id="main" width="600" align="center" cellpadding="0" cellspacing="15" bgcolor="3b3c45">
                    <tr>
                    <td>
                        <table id="header" cellpadding="10" cellspacing="0" align="center" bgcolor="8fb3e9">
                        <tr>
                            <td width="570" align="center"  bgcolor="#3b3c45"><h1 style="color:#ffffff">Scanner Tools</h1></td>
                        </tr>
                        <tr>
                            <td width="570" align="center" bgcolor="#3b3c45"><p style="color:#ffffff">Vulnerabilidades en tu red</td>
                        </tr>
                        </table>
                    </td>
                    </tr>
                
                    <tr>
                    <td>
                        <table id="content-3" cellpadding="0" cellspacing="0" align="center">
                        <tr>
                            <td width="15"></td>
                            <td width="250" valign="top" bgcolor="3b3c45" style="padding:5px;">
                                <img src="https://i.ibb.co/hMfRbzs/portada.png" width ="250" height="150" />
                            </td>
                        </tr>
                        </table>
                    </td>
                    </tr>
                    <tr>
                    <td>
                        <table id="content-4" cellpadding="0" cellspacing="0" align="center">
                        <tr>
                            <td width="15"></td>
                            <td width="200" valign="top">
                            <h5 style="color:#ffffff">Su contraseña fue cambiada. </h5>
                            <p class="w" style="color:#ffffff">La nueva contraseña para el usuario {you} es :</p>
                            <p class="w" style="color:#ffffff">{contraseña}</p>
                            </td>
                        </tr>
                        </table>
                    </td>
                    </tr>
                    
                
                </table>

                <table id="bottom" cellpadding="20" cellspacing="0" width="600" align="center">
                    <tr>
                    <td align="center">
                        <p style="color:#ffffff">Tecnologias de la Informacion y Comunicacion Infraestructura de Redes Digitales</p>
                        
                    </td>
                    </tr>
                </table>


                
                </body>
                </html>
                    

            """
        part2 = MIMEText(html, 'html')
        msg.attach(part2)
        mail = smtplib.SMTP('smtp.gmail.com', 587)
        mail.ehlo()
        mail.starttls()
        mail.login('scannertoolsutt@gmail.com', 'AsDfGhJk')
        mail.sendmail(me, you, msg.as_string())
        mail.quit()
        contraseña = bcrypt.generate_password_hash(contraseña).decode('utf-8')

        cur = sqlite3.connect("base_datos.db")
        cursor = cur.cursor()
        cursor.execute(f'UPDATE usuario SET contraseña = "{contraseña}" WHERE correo = "{you}"')
        cur.commit()

        flash('Verifique la bandeja de entrada de su correo.')
        return redirect(url_for('autenticacion'))

    except:
        flash("Ocurrio un error, intentelo nuevamente.")
        return redirect(url_for('autenticacion'))
    

    



if __name__ == '__main__':
    app.run(debug=True)

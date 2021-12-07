import os
import datetime
from base64 import b64encode, b64decode
import requests
import jwt
from bs4 import BeautifulSoup
from ics import Calendar, Event
from flask import Flask, request, render_template
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import arrow


# ASEGÚRESE DE CONFIGURAR LA VARIABLE DE ENTORNO 'SECRET' CON UN STRING ALEATORIO CRIPTOGRÁFICAMENTE SEGURO
SECRET = os.environ.get('SECRET')


def td_login(username, password):
    # Crea una sesión de requests
    session = requests.Session()
    login_response = session.post('https://tecdigital.tec.ac.cr/api/login/new-form/',
                                  allow_redirects=False, timeout=10, verify=False, json={
                                      "email": username,
                                      "password": password,
                                      "retoken": "allow",
                                      "returnUrl": "/dotlrn/index"

                                  })

    # Revisa potenciales respuestas del TD
    if login_response.json()['status'] == 'no_account':
        raise EnvironmentError('El usuario es incorrecto.')
    if login_response.json()['status'] == 'datic_bad_password':
        raise EnvironmentError('La contraseña es incorrecta.')
    if login_response.json()['status'] != 'ok':
        raise EnvironmentError('El TEC Digital está caído.')

    return session


def get_calendar(user, password):
    # Verifica inicio de sesión correcto
    session = td_login(user, password)
    date = datetime.datetime.today()
    response = session.get('https://tecdigital.tec.ac.cr/dotlrn/calendar/view?date=' + date.strftime('%Y-%m-%d') + '&view=list&page_num=1&period_days=90',
                           allow_redirects=False, timeout=10, verify=False)

    # Decidí usar EnvironmentError para erorres de datos de login
    if response.status_code != 200:
        raise EnvironmentError(
            'Los datos son incorrectos o el TEC Digital está caído.')

    # Crea el iCal
    cal = Calendar()

    # Parsea eventos del HTML
    events = []

    try:
        soup = BeautifulSoup(response.content, features='lxml')
        table = soup.find('table', attrs={'class': 'list-table'})
        table_body = table.find('tbody')
    except Exception as e:
        raise Exception(
            'No se ha podido leer su calendario del TEC Digital. Reportar este error. Detalles: ' + str(e))

    try:
        rows = table_body.find_all('tr')
        for row in rows:
            cols = row.find_all('td')
            cols = [ele.text.strip() for ele in cols]
            # elimina elementos vacíos
            events.append([ele for ele in cols if ele])
    except Exception as e:
        raise Exception(
            'No se ha podido parsear el calendario. Por favor reportar este error. Detalles: ' + str(e))

    for event_data in events:
        # Comprobación necesaria en caso de calendario vacío
        if len(event_data) < 4:
            continue

        e = Event()
        e.name = f'{event_data[2]} - {event_data[3]}'
        # HOTFIX: eventos sin descripción
        try:
            e.description = event_data[4].replace(
                'Pulse aquí para ir a', 'Puede encontrar más detalles en')
        except IndexError:
            e.description = ""
        date = arrow.get(event_data[0], 'DD MMMM YYYY', locale='es').replace(
            tzinfo='America/Costa_Rica')
        e.begin = date
        if event_data[1] == 'Evento para todo el día':
            e.make_all_day()
        else:
            # HOTFIX: el TEC Digital de alguna forma permite horas inválidas, hace eventos all_day si no puede parsear
            try:
                e.begin = arrow.get(event_data[0] + ' ' + event_data[1][0:5],
                                    'DD MMMM YYYY HH:mm', locale='es').replace(tzinfo='America/Costa_Rica')
                e.end = arrow.get(event_data[0] + ' ' + event_data[1][8:],
                                  'DD MMMM YYYY HH:mm', locale='es').replace(tzinfo='America/Costa_Rica')
            except:
                e.make_all_day()
        cal.events.add(e)

    return cal


def get_calendar_warning_outdated():
    # Genera un evento falso para alertar a los usuarios que están usando un calendario obsoleto
    cal = Calendar()
    e = Event()
    e.name = 'ACCIÓN NECESARIA: Debe actualizar su calendario del TEC Digital'
    e.description = "Hola.\n\nHace un tiempo utilizó una herramienta para sincronizar el calendario de "\
        "sus cursos del TEC Digital con su calendario personal. Recientemente el TEC Digital cambió el "\
        "inicio de sesión y ahora se usa la cuenta de @estudiantec.cr, por lo que debe volver a realizar la "\
        "sincronización.\n\nPara hacerlo entre a la página https://tdcal.josvar.com y siga las instrucciones "\
        "nuevamente.\n\nSaludos, Joseph."
    e.begin = datetime.datetime.now()
    e.make_all_day()
    cal.events.add(e)
    return cal


# Carga Flask
app = Flask(__name__)


# Página principal
@app.route("/")
def index():
    return render_template("index.html")

# Generación de tokens JWT


@app.route('/tokens', methods=['POST'])
def create_token():
    try:
        if not SECRET:
            raise Exception(
                "La variable de entorno SECRET no se ha inicializado.")

        user = request.form['user'].strip().lower()
        password = request.form['password'].strip()

        # Intenta obtener el calendario para verificar los datos de inicio de sesión
        get_calendar(user, password)

        # Inicializa AES con un IV aleatorio, se limita la llave de encriptación a 32 bytes / 256 bits
        iv = get_random_bytes(16)
        cipher = AES.new(SECRET[0:32].encode('utf-8'), AES.MODE_CFB, iv)

        # Encripta los datos de usuario y contraseña
        user = b64encode(cipher.encrypt(user.encode('utf-8'))).decode('utf-8')
        password = b64encode(cipher.encrypt(
            password.encode('utf-8'))).decode('utf-8')
        iv = b64encode(iv).decode('utf-8')

        # Genera un token JWT con los datos encriptados
        encoded_jwt = jwt.encode(
            {'user': user, 'password': password, 'iv': iv, 'version': '1.1'}, SECRET, algorithm='HS256')

        return f'https://tdcal.josvar.com/{encoded_jwt}/cal.ics'

    except EnvironmentError as e:
        return f'Ha ocurrido un error: {e}', 400

    except requests.exceptions.Timeout:
        return 'El TEC Digital está caído. Por favor inténtelo de nuevo más tarde.', 503

    except Exception as e:
        return f'Ha ocurrido un error: {e}', 500

# Ruta para descargar el calendario tomando un token JWT


@app.route('/<token>/cal.ics', methods=['GET'])
def read_calendar(token):
    try:
        if not SECRET:
            raise Exception(
                "La variable de entorno SECRET no se ha inicializado.")

        # Decodifica el token
        data = jwt.decode(token, SECRET, algorithms=['HS256'])

        print(data)

        # Alerta a los usuarios que están usando la versión 1.0
        if 'version' not in data:
            return str(get_calendar_warning_outdated()), 200, {'Content-Type': 'text/calendar; charset=utf-8'}

        # Desencripta el usuario y contraseña
        if "iv" in data:
            cipher = AES.new(SECRET[0:32].encode(
                'utf-8'), AES.MODE_CFB, b64decode(data['iv']))
            user = cipher.decrypt(b64decode(data['user'])).decode('utf-8')
            password = cipher.decrypt(
                b64decode(data['password'])).decode('utf-8')
        else:
            user = data['user']
            password = data['password']

        cal = get_calendar(user, password)

        # HOTFIX: Agrego manualmente el nombre del cal al ics ya que la biblioteca no lo soporta
        cal = str(cal).replace(
            'PRODID:ics.py - http://git.io/lLljaA', 'X-WR-CALNAME:TEC Digital')

        return cal, 200, {'Content-Type': 'text/calendar; charset=utf-8'}

    except requests.exceptions.Timeout:
        return 'El TEC Digital está caído. Por favor inténtelo de nuevo más tarde.', 503

    except Exception as e:
        return f'Ha ocurrido un error: {e}', 500


# Inicialización Flask
port = int(os.environ.get('PORT', 8080))
if __name__ == '__main__':
    app.run(threaded=True, host='0.0.0.0', port=port)

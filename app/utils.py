import logging
import os
from datetime import datetime
from django.utils.html import escape
from pytz import timezone
from django.conf import settings
from app.models import Event, CustomUser
import subprocess
from django.shortcuts import redirect
import platform

def syslog_message(text,level):
    logger = logging.getLogger('ShoPYME')

    if level == 'INFO':
        logger.info(text)

def logPrintEvents(text,level='INFO'):
    print("[DAEMON] "+text)
    date = datetime.now(timezone(settings.TIME_ZONE))
    syslog_message(text,level)

    Event.objects.create(description=text, date=date.strftime("%Y-%m-%d %H:%M:%S"))
    
    
class Notification():
    def __init__(self,type,message):
        self.type = type
        self.message = message
        

def getStatus(request):
    try:
        logs = []
        for e in Event.objects.order_by("-pk")[:10]:
            description = escape(e.description)
            description = description[:360] + '....' if len(description) > 360 else description
            logs.append({'date':e.date.strftime("%d/%m/%Y %H:%M:%S"), 'description': description})

        notf = '' if os.environ.get('notf_loged') == None or os.environ.get('user_loged') != str(request.user) else os.environ.get('notf_loged')
        notf_type = '' if os.environ.get('notftype_loged') == None or os.environ.get('user_loged') != str(request.user) else os.environ.get('notftype_loged')

        os.environ['notf_loged'] = ''
        os.environ['notftype_loged'] = ''
        if str(notf) != '' and str(notf_type) != '':
            os.environ['user_loged'] = ''

        #stats = Stadistic.objects.first()
        
        return {'logs':logs, 'notf':notf, 'notf_type': notf_type}
    except:
        print("e")
        return {'logs':'', 'notf':'', 'notf_type': '' }
    
def getInfoMessages():
    return(
        {
            'logs':'En esta sección se listan los eventos relevantes (logs) del daemon, el proceso que consulta periódicamente Nozomi para detectar y analizar nuevos activos o alertas.',
            'scans_list':'Esta es la lista de los servicios ya escaneados y guardados dentro de la red, puedes acceder a los detalles de cada uno de ellos pulsando en el identificador o añadir nuevo escaneo para añadir más servicios.',
            'scans_search':'Esta es la vista del buscador de activos y servicios de la aplicación. A traves del buscador (introduciendo una query) podras ver una serie de resultados los cuales añadir como objetivo de tu escaneo.',
            'details_scan':'Esta es la vista detallada del servicio escaneado donde por un lado podras ver la información general del mismo, puertos abiertos, posibles certificados ssh, entre otras cosas.',
            'identifier':'Aqui puedes establecer la manera en la que quieres indentificar el servicio estableciendo cualquier nombre o código',
            'notes':'Además del identificador puedes escribir notas adicionales al mismo',
            'vulnerabilities':'Aqui se muestran todas las vulnerabilidades recopiladas de los diferentes servicios escaneados (Si has borrado alguno de los activos ya escaneados, puede que algunos de estas vulnerabilidades ya no apliquen si ha borrado el único host asociado a esta vulnerabilidad)',
            'configuration_about':'En este apartado puede encontrar el acuerdo legal para el uso de la herramienta.',
            'configuration_pass_change':'En este apartado puede cambiar la contraseña de la cuenta, simplemente indicando la contraseña actual y estableciendo una nueva.',
            'monitorization':'En este apartado podras (si cuentas con una api adeacuada) establecer unos objetivo de monitorización para que la aplicación te aviso de cualquier cambio que se produzcan en ellos',
            'monitorizationForm':'Marcando la casilla habilitas la monitorización y en el campo de texto puedes establecer separado por comas las ips a monitorizar (las cuales dependeran de tu plan con la api)',
        }
    )
    
def is_shopyme_admin(request):
    id_user = request.user.id
    shopyme_user = CustomUser.objects.filter(user_id=id_user).get()
    return shopyme_user.shopyme
    
def countryLanguage(country):
    countries = {
    "Afghanistan": "Afganistán",
    "Albania": "Albania",
    "Germany": "Alemania",
    "Algeria": "Argelia",
    "Andorra": "Andorra",
    "Angola": "Angola",
    "Anguilla": "Anguila",
    "Antarctica": "Antártida",
    "Antigua and Barbuda": "Antigua y Barbuda",
    "Netherlands Antilles": "Antillas Neerlandesas",
    "Saudi Arabia": "Arabia Saudita",
    "Argentina": "Argentina",
    "Armenia": "Armenia",
    "Aruba": "Aruba",
    "Australia": "Australia",
    "Austria": "Austria",
    "Azerbaijan": "Azerbayán",
    "Belgium": "Bélgica",
    "Bahamas": "Bahamas",
    "Bahrain": "Bahréin",
    "Bangladesh": "Bangladesh",
    "Barbados": "Barbados",
    "Belize": "Belice",
    "Benin": "Benín",
    "Bhutan": "Bután",
    "Belarus": "Bielorrusia",
    "Myanmar": "Birmania",
    "Bolivia": "Bolivia",
    "Bosnia and Herzegovina": "Bosnia y Herzegovina",
    "Botswana": "Botsuana",
    "Brazil": "Brasil",
    "Brunei": "Brunéi",
    "Bulgaria": "Bulgaria",
    "Burkina Faso": "Burkina Faso",
    "Burundi": "Burundi",
    "Cape Verde": "Cabo Verde",
    "Cambodia": "Camboya",
    "Cameroon": "Camerún",
    "Canada": "Canadá",
    "Chad": "Chad",
    "Chile": "Chile",
    "China": "China",
    "Cyprus": "Chipre",
    "Vatican City State": "Ciudad del Vaticano",
    "Colombia": "Colombia",
    "Comoros": "Comoras",
    "Congo": "Congo",
    "North Korea": "Corea del Norte",
    "South Korea": "Corea del Sur",
    "Ivory Coast": "Costa de Marfil",
    "Costa Rica": "Costa Rica",
    "Croatia": "Croacia",
    "Cuba": "Cuba",
    "Denmark": "Dinamarca",
    "Dominica": "Dominica",
    "Ecuador": "Ecuador",
    "Egypt": "Egipto",
    "El Salvador": "El Salvador",
    "United Arab Emirates": "Emiratos Árabes Unidos",
    "Eritrea": "Eritrea",
    "Slovakia": "Eslovaquia",
    "Slovenia": "Eslovenia",
    "Spain": "España",
    "United States of America": "Estados Unidos de América",
    "Estonia": "Estonia",
    "Ethiopia": "Etiopía",
    "Philippines": "Filipinas",
    "Finland": "Finlandia",
    "Fiji": "Fiyi",
    "France": "Francia",
    "Gabon": "Gabón",
    "Gambia": "Gambia",
    "Georgia": "Georgia",
    "Ghana": "Ghana",
    "Gibraltar": "Gibraltar",
    "Grenada": "Granada",
    "Greece": "Grecia",
    "Greenland": "Groenlandia",
    "Guadeloupe": "Guadalupe",
    "Guam": "Guam",
    "Guatemala": "Guatemala",
    "French Guiana": "Guayana Francesa",
    "Guernsey": "Guernsey",
    "Guinea": "Guinea",
    "Equatorial Guinea": "Guinea Ecuatorial",
    "Guinea-Bissau": "Guinea-Bissau",
    "Guyana": "Guyana",
    "Haiti": "Haití",
    "Honduras": "Honduras",
    "Hong Kong": "Hong Kong",
    "Hungary": "Hungría",
    "India": "India",
    "Indonesia": "Indonesia",
    "Iran": "Irán",
    "Iraq": "Irak",
    "Ireland": "Irlanda",
    "Bouvet Island": "Isla Bouvet",
    "Isle of Man": "Isla de Man",
    "Christmas Island": "Isla de Navidad",
    "Norfolk Island": "Isla Norfolk",
    "Iceland": "Islandia",
    "Bermuda Islands": "Islas Bermudas",
    "Cayman Islands": "Islas Caimán",
    "Cocos (Keeling) Islands": "Islas Cocos (Keeling)",
    "Cook Islands": "Islas Cook",
    "Åland Islands": "Islas de Åland",
    "Faroe Islands": "Islas Feroe",
    "South Georgia and the South Sandwich Islands": "Islas Georgias del Sur y Sandwich del Sur",
    "Heard Island and McDonald Islands": "Islas Heard y McDonald",
    "Maldives": "Islas Maldivas",
    "Falkland Islands (Malvinas)": "Islas Malvinas",
    "Northern Mariana Islands": "Islas Marianas del Norte",
    "Marshall Islands": "Islas Marshall",
    "Pitcairn Islands": "Islas Pitcairn",
    "Solomon Islands": "Islas Salomón",
    "Turks and Caicos Islands": "Islas Turcas y Caicos",
    "United States Minor Outlying Islands": "Islas Ultramarinas Menores de Estados Unidos",
    "Virgin Islands": "Islas Vírgenes Británicas",
    "United States Virgin Islands": "Islas Vírgenes de los Estados Unidos",
    "Israel": "Israel",
    "Italy": "Italia",
    "Jamaica": "Jamaica",
    "Japan": "Japón",
    "Jersey": "Jersey",
    "Jordan": "Jordania",
    "Kazakhstan": "Kazajistán",
    "Kenya": "Kenia",
    "Kyrgyzstan": "Kirgizstán",
    "Kiribati": "Kiribati",
    "Kuwait": "Kuwait",
    "Lebanon": "Líbano",
    "Laos": "Laos",
    "Lesotho": "Lesoto",
    "Latvia": "Letonia",
    "Liberia": "Liberia",
    "Libya": "Libia",
    "Liechtenstein": "Liechtenstein",
    "Lithuania": "Lituania",
    "Luxembourg": "Luxemburgo",
    "Mexico": "México",
    "Monaco": "Mónaco",
    "Macao": "Macao",
    "Macedonia": "Macedônia",
    "Madagascar": "Madagascar",
    "Malaysia": "Malasia",
    "Malawi": "Malawi",
    "Mali": "Mali",
    "Malta": "Malta",
    "Morocco": "Marruecos",
    "Martinique": "Martinica",
    "Mauritius": "Mauricio",
    "Mauritania": "Mauritania",
    "Mayotte": "Mayotte",
    "Estados Federados de": "Micronesia",
    "Moldova": "Moldavia",
    "Mongolia": "Mongolia",
    "Montenegro": "Montenegro",
    "Montserrat": "Montserrat",
    "Mozambique": "Mozambique",
    "Namibia": "Namibia",
    "Nauru": "Nauru",
    "Nepal": "Nepal",
    "Nicaragua": "Nicaragua",
    "Niger": "Niger",
    "Nigeria": "Nigeria",
    "Niue": "Niue",
    "Norway": "Noruega",
    "New Caledonia": "Nueva Caledonia",
    "New Zealand": "Nueva Zelanda",
    "Oman": "Omán",
    "Netherlands": "Países Bajos",
    "Pakistan": "Pakistán",
    "Palau": "Palau",
    "Palestine": "Palestina",
    "Panama": "Panamá",
    "Papua New Guinea": "Papúa Nueva Guinea",
    "Paraguay": "Paraguay",
    "Peru": "Perú",
    "French Polynesia": "Polinesia Francesa",
    "Poland": "Polonia",
    "Portugal": "Portugal",
    "Puerto Rico": "Puerto Rico",
    "Qatar": "Qatar",
    "United Kingdom": "Reino Unido",
    "Central African Republic": "República Centroafricana",
    "Czech Republic": "República Checa",
    "Dominican Republic": "República Dominicana",
    "Réunion": "Reunión",
    "Rwanda": "Ruanda",
    "Romania": "Rumanía",
    "Russia": "Rusia",
    "Western Sahara": "Sahara Occidental",
    "Samoa": "Samoa",
    "American Samoa": "Samoa Americana",
    "Saint Barthélemy": "San Bartolomé",
    "Saint Kitts and Nevis": "San Cristóbal y Nieves",
    "San Marino": "San Marino",
    "Saint Martin (French part)": "San Martín (Francia)",
    "Saint Pierre and Miquelon": "San Pedro y Miquelón",
    "Saint Vincent and the Grenadines": "San Vicente y las Granadinas",
    "Ascensión y Tristán de Acuña": "Santa Elena",
    "Saint Lucia": "Santa Lucía",
    "Sao Tome and Principe": "Santo Tomé y Príncipe",
    "Senegal": "Senegal",
    "Serbia": "Serbia",
    "Seychelles": "Seychelles",
    "Sierra Leone": "Sierra Leona",
    "Singapore": "Singapur",
    "Syria": "Siria",
    "Somalia": "Somalia",
    "Sri Lanka": "Sri Lanka",
    "Swaziland": "Suazilandia",
    "South Africa": "Sudáfrica",
    "Sudan": "Sudán",
    "South Sudan": "Sudán del Sur",
    "Sweden": "Suecia",
    "Switzerland": "Suiza",
    "Suriname": "Surinam",
    "Svalbard and Jan Mayen": "Svalbard y Jan Mayen",
    "Thailand": "Tailandia",
    "Taiwan": "Taiwán",
    "Tanzania": "Tanzania",
    "Tajikistan": "Tayikistán",
    "British Indian Ocean Territory": "Territorio Británico del Océano Índico",
    "French Southern Territories": "Territorios Australes Franceses",
    "Palestinian Territories": "Territorios Palestinos",
    "East Timor": "Timor Oriental",
    "Togo": "Togo",
    "Tokelau": "Tokelau",
    "Tonga": "Tonga",
    "Trinidad and Tobago": "Trinidad y Tobago",
    "Tunisia": "Túnez",
    "Turkmenistan": "Turkmenistán",
    "Turkey": "Turquía",
    "Tuvalu": "Tuvalu",
    "Ukraine": "Ucrania",
    "Uganda": "Uganda",
    "Uruguay": "Uruguay",
    "Uzbekistan": "Uzbekistán",
    "Vanuatu": "Vanuatu",
    "Venezuela": "Venezuela",
    "Vietnam": "Vietnam",
    "Wallis and Futuna": "Wallis y Futuna",
    "Yemen": "Yemen",
    "Djibouti": "Yibuti",
    "Zambia": "Zambia",
    "Zimbabwe": "Zimbabue"
    }
    return countries.get(country, country)

def restart_django(request):
    so = platform.system()
    if so == "Linux":
        subprocess.run(["pkill", "-f", "runserver"])
    
    elif so == "Windows":
        subprocess.run(["taskkill", "/F", "/IM", "python.exe"])

    subprocess.Popen(["python3", "manage.py", "runserver"])

        
    return redirect('/monitorization')  # Reemplaza 'nombre_de_la_vista' con el nombre real de tu vista
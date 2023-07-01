from django.core.management.base import BaseCommand
import sqlite3
from app.models import Host, Event, Vulnerability
import json

models = ['Event', 'Configuration', 'Stadistic', 'Rule', 'Tag', 'Zone', 'SubZone']
d = {'data': 'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 56036\r\nSet-Cookie: JSESSIONID=deleted; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Path=/; HttpOnly\r\nConnection: keep-alive\r\n\r\n', 'port': 443, 'ip_str': '78.136.75.111'}


class Command(BaseCommand):
    args = '<foo bar ...>'
    help = 'our help string comes here'

    def empty_database(self):
        Event.objects.all().delete()
        Host.objects.all().delete()
        Vulnerability.objects.all().delete()
    def populate_database(self):
        # Hosts
        Host.objects.create(identifier='Prueba', data_json=json.dumps(d))

    def handle(self, *args, **options):
        self.empty_database()

        connection = sqlite3.connect('db.sqlite3')
        cursor = connection.cursor()
        for model in models:
            cursor.execute("delete from sqlite_sequence where name = '{:s}';".format('app_'+model).lower())
        connection.commit()
        connection.close()

        self.populate_database()
        print('Base de datos populada')


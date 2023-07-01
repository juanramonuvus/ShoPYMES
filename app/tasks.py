import time
from threading import Thread
from shodan import Shodan
from shodan.helpers import get_ip
from app.utils import logPrintEvents
from app.models import Configuration, AlertMonitorization

SHODAN_API_KEY = 's1a8ZMKMWFnfvqNy20QsFMMfPI92mhh0'
api = Shodan(SHODAN_API_KEY)

class PeriodicMonitorizationFunction(Thread):
    def __init__(self):
        super(PeriodicMonitorizationFunction, self).__init__()
        
    def run(self):
        
        time.sleep(2)
        
        while True:
            if Configuration.objects.first().monitorization:
                for banner in api.stream.alert():
                    # Check whether the banner is from an ICS service
                    if 'tags' in banner and 'ics' in banner['tags']:
                        ip = get_ip(banner)
                        alert = AlertMonitorization(description="Alerta: "+str(ip)+"""
                        Información del servicio de monitorización:

                        Port: {port}
                        Data: {data}

                        """.format(banner))
                        alert.save()
                        logPrintEvents('El servicio de monitorización ha detectado un cambio en una de las ips establecidas')
                        
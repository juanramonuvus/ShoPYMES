import json
import ast
import nvdlib
import goslate
import csv
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login, logout
from app.utils import Notification, syslog_message, getStatus, getInfoMessages, logPrintEvents, is_shopyme_admin, countryLanguage, restart_django
from app.models import Event, Host, Vulnerability, AlertMonitorization, Configuration
from django.core.paginator import Paginator
from django.contrib.auth.models import User
import shodan
from app.forms import LoginForm, ConfigChangePassForm, ShodanSubmit, MonitorizationForm, ShodanSearch, ScanForm

infoMessages = getInfoMessages()

SHODAN_API_KEY = 's1a8ZMKMWFnfvqNy20QsFMMfPI92mhh0'
api = shodan.Shodan(SHODAN_API_KEY)
gs = goslate.Goslate()

# Create your views here.
@login_required
def home(request):
    status = getStatus(request)
    n_hosts = Host.objects.all().count()
    n_vulns = Vulnerability.objects.all().count()
    monitorization = Configuration.objects.first().monitorization
    return render(request, 'dashboard.html', {'infoMessage':infoMessages, 'username':request.user, 'status': status, 'n_hosts':n_hosts, 'n_vulns':n_vulns, 'monitorization':monitorization})

def login_user(request):
    if not request.user.is_authenticated:
        form = LoginForm()
        if request.method == 'POST':
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                syslog_message('Sesión iniciada con el usuario: '+str(user),'INFO')
                logPrintEvents('El usuario '+str(user)+" ha iniciado sesión")
                return redirect('/')
            else:
                syslog_message('Intento de inicio de sesión fallido con el usuario: '+str(user),'INFO')
                return render(request, 'login.html', {'form': form, 'notification':Notification('error', 'Usuario o contraseña incorrectos')})
        return render(request, 'login.html', {'form': form})
    else:
        return redirect('/')

@login_required
def logut_user(request):
    logout(request)
    return redirect('/login')

@login_required
def scans(request):
    booleanAdmin = is_shopyme_admin(request)
    scans_get = Host.objects.all().order_by('pk').reverse()
    #scans_get = Rule.objects.all().order_by('priority', 'pk').reverse()
    scans = []

    for s in scans_get:
        scan = dict()
    
        scan['identifier'] = s.identifier
        j = json.loads(s.data_json)
        scan['conditions'] = j['data'] if 'data' in s.data_json else ''
        scan['pk'] = s.pk
        scan['notes'] = s.notes
        scans.append(scan)


    paginator = Paginator(scans, 10)
    page = 1
    if 'page' in request.GET:
        page = int(request.GET.get('page'))
        
    if request.session.get('notification') != None:
        notification = request.session.get('notification')
        notification_type = request.session.get('notification_type')
        request.session['notification'] = None
        request.session['notification_type'] = None
        return render(request, 'scans.html', {'infoMessage':infoMessages,'status':getStatus(request),'username':request.user,'scans': paginator.get_page(page),'page':page , 'hasPrevious':paginator.page(page).has_previous(), 'hasNext':paginator.page(page).has_next(), 'notification':Notification(notification_type, notification), 'booleanAdmin':booleanAdmin})
    else:
        return render(request, 'scans.html', {'infoMessage':infoMessages,'status':getStatus(request),'username':request.user,'scans': paginator.get_page(page),'page':page , 'hasPrevious':paginator.page(page).has_previous(), 'hasNext':paginator.page(page).has_next(), 'booleanAdmin':booleanAdmin})

@login_required
def vulnerabilities(request):
    booleanAdmin = is_shopyme_admin(request)
    vulnerabilities_get = Vulnerability.objects.all().order_by('identifier')
    print(vulnerabilities_get)
    #scans_get = Rule.objects.all().order_by('priority', 'pk').reverse()
    vulnerabilities = []

    for v in vulnerabilities_get:
        vuln = dict()
    
        vuln['identifier'] = v.identifier
        vuln['description'] = v.description
        vulnerabilities.append(vuln)

    
    paginator = Paginator(vulnerabilities, 10)
    page = 1
    if 'page' in request.GET:
        page = int(request.GET.get('page'))
        
    if request.session.get('notification') != None:
        notification = request.session.get('notification')
        notification_type = request.session.get('notification_type')
        print(notification)
        print(notification_type)
        request.session['notification'] = None
        request.session['notification_type'] = None
        return render(request, 'vulnerabilities.html', {'infoMessage':infoMessages,'status':getStatus(request),'username':request.user,'vulnerabilities': paginator.get_page(page),'page':page , 'hasPrevious':paginator.page(page).has_previous(), 'hasNext':paginator.page(page).has_next(), 'notification':Notification(notification_type, notification), 'booleanAdmin':booleanAdmin})
    else:
        return render(request, 'vulnerabilities.html', {'infoMessage':infoMessages,'status':getStatus(request),'username':request.user,'vulnerabilities': paginator.get_page(page),'page':page , 'hasPrevious':paginator.page(page).has_previous(), 'hasNext':paginator.page(page).has_next(), 'booleanAdmin':booleanAdmin})

@login_required
def delete_vulnerability(request, vuln_str):
    booleanAdmin = is_shopyme_admin(request)
    if booleanAdmin:
        vuln = Vulnerability.objects.get(pk=vuln_str)
        i = vuln.identifier
        vuln.delete()
        syslog_message('Vulnerabilidad "'+str(i)+'" eliminada por el usuario: '+str(request.user),'INFO')
        logPrintEvents('Vulnerabilidad "'+str(i)+'" eliminada por el usuario: '+str(request.user))
        request.session['notification'] = 'Se han eliminado correctamente'
        request.session['notification_type'] = 'correct'
        return redirect('/vulnerabilities')
        
@login_required
def add_scan(request):
    booleanAdmin = is_shopyme_admin(request)
    cves = Vulnerability.objects.values_list('identifier', flat=True)
    searchForm = ShodanSearch
    submitForm = ShodanSubmit
    if booleanAdmin:
        search_scans = []
        if request.method == 'POST':
            if request.POST['identifier'] == 'search':
                searchForm = ShodanSearch(request.POST)
                submitForm = ShodanSubmit
                ips = []
                query = searchForm['search'].value()
                res = api.search(query)
                id = 0
                if len(res['matches']) != 0:
                    for r in res['matches']:
                        match = dict()
                        if r['ip_str'] not in ips:
                            match['id'] = str(id)
                            match['ip_str'] = r['ip_str'] if r['ip_str'] else 'N/A'
                            match['org'] = r['org'] if r['org'] else 'N/A'
                            match['city'] = r['location']['city'] if r['location']['city'] else 'N/A'
                            match['country_name'] = r['location']['country_name'] if r['location']['country_name'] else 'N/A'
                            match['data'] = r['data'] if r['data'] else 'N/A'
                            if (match['ip_str'] != "N/A" and match['data'] != 'N/A'):
                                search_scans.append(match)
                            id+=1
                            ips.append(r['ip_str'])
                    return render(request, 'add_scan.html', {'infoMessage':infoMessages,'status':getStatus(request),'username':request.user, 'booleanAdmin':booleanAdmin, 'searchForm':searchForm, 'submitForm':submitForm, 'search_scans':search_scans})
                    #results = api.search('city:"Córdoba" country:"ES" city:"Villaviciosa de Córdoba"')
                else:
                    notification = 'No se ha encontrado ningun activo con esa query'
                    notification_type = 'error'
                    return render(request, 'add_scan.html', {'notification':Notification(notification_type, notification), 'infoMessage':infoMessages,'status':getStatus(request),'username':request.user, 'booleanAdmin':booleanAdmin, 'searchForm':searchForm, 'submitForm':submitForm, 'search_scans':search_scans})
            elif request.POST['identifier'] == 'submit':
                search_scans = ast.literal_eval(request.POST['search_scans'])
                assets_selected = [request.POST[r] for r in request.POST if 'asset' in r]
                for a in search_scans:
                    if a.get('id') in assets_selected:
                        try:
                            ipinfo = api.host(a.get('ip_str'))
                            host = Host(identifier=a.get('ip_str')+' - '+a.get('id'), data_json=json.dumps(ipinfo))
                            host.save()
                            if ipinfo.get('vulns') is not None:
                                for vuln in ipinfo['vulns']:
                                    if str(vuln) not in cves:
                                        try:
                                            cveInfo = nvdlib.searchCVE(cveId=str(vuln))[0]
                                            description = gs.translate(cveInfo.descriptions[0].value, 'es') 
                                            vulnerability = Vulnerability(identifier=str(vuln), description=str(description))
                                            vulnerability.save()
                                        except:
                                            pass
                            
                        except:
                            notification = 'Ha ocurrido un error al buscar información de la ip: '+a.get('ip_str')+' intentelo de nuevo.'
                            notification_type = 'error'
                            return render(request, 'add_scan.html', {'notification':Notification(notification_type, notification), 'infoMessage':infoMessages,'status':getStatus(request),'username':request.user, 'booleanAdmin':booleanAdmin, 'searchForm':searchForm, 'submitForm':submitForm, 'search_scans':search_scans}) 
                
                syslog_message('Se ha guardado '+str(len(assets_selected))+' servicios por el usuario: '+str(request.user), 'INFO')     
                logPrintEvents('Se ha guardado '+str(len(assets_selected))+' servicios por el usuario: '+str(request.user))
                
                request.session['notification'] = 'Se han añadido correctamente'
                request.session['notification_type'] = 'correct'
                
                return redirect('/scans')
    
        return render(request, 'add_scan.html', {'infoMessage':infoMessages,'status':getStatus(request),'username':request.user, 'booleanAdmin':booleanAdmin, 'searchForm':searchForm, 'submitForm':submitForm, 'search_scans':search_scans})
    else:
        return redirect('/scans')
  
@login_required
def details_scan(request, host_id):
    booleanAdmin = is_shopyme_admin(request)
    host = Host.objects.get(pk=host_id)
    
    information_dict = json.loads(host.data_json)
    
    ip = information_dict['ip_str'] if information_dict.get('ip_str') is not None else 'No hay dirección ip'
    country_name = countryLanguage(information_dict['country_name']) if information_dict.get('country_name') is not None else 'No se especifica país'
    city = information_dict['city'] if information_dict.get('city') is not None else 'No se especifica ciudad'
    org = information_dict['org'] if information_dict.get('org') is not None else 'No se especifica organización'
    isp = information_dict['isp'] if information_dict.get('isp') is not None else 'No se especifica isp'
        
    general_information = {'ip':ip, 'country_name': country_name, 'city':city, 'org':org, 'isp':isp}
    
    services = []
    for info in information_dict['data']:
        i = dict()
        i['port'] = info['port'] if info.get('port') is not None else 0
        i['transport'] = info['transport'] if info.get('transport') is not None else 'No protocolo'
        i['status'] = str(info['http']['status']) if info.get('http') is not None else '500'
        i['product'] = info['product'] if info.get('product') is not None else ''
        
        if info.get('data') is not None:
            data = info['data'].replace('rn', '\n')
            i['data'] = data
        else:
            i['data'] = 'Sin datos'
            
        if info.get('ssh') is not None:
            try:
                ssh = "Certificate:<br>"
                ssh += "Data:<br>"
                ssh += f"Version: {info['ssh']['cert']['version']} (0x{info['ssh']['cert']['version']:X})<br>"
                ssh += f"Serial Number: {info['ssh']['cert']['serial']} (0x{info['ssh']['cert']['serial']:X})<br>"
                ssh += f"Signature Algorithm: {info['ssh']['cert']['sig_alg']}<br>"
                i['ssh'] = ssh
            except:
                i['ssh']=''
        else:
            i['ssh'] = ''
        
        services.append(i)
    
    if request.method == 'POST':
        newForm = ScanForm(request.POST)
        if not booleanAdmin:
            return render(request, 'details_zone.html', {'infoMessage':infoMessages,'status':getStatus(request),'username':request.user, 'pk':host_id, 'booleanAdmin':booleanAdmin, 'form':newForm, 'general_information':general_information, 'services':services, 'notification':Notification('error', 'No tiene los permisos necesarios para realizar esta acción'), 'booleanAdmin':booleanAdmin})
        
        if newForm.is_valid():
            Host.objects.filter(pk=host_id).update(identifier=newForm['identifier'].value(), notes=newForm['notes'].value())
            
            syslog_message('Servicio modificado por el usuario: '+str(request.user),'INFO')
            logPrintEvents('Servicio '+str(newForm['identifier'].value())+' modificado por el usuario: '+str(request.user))
            
            return render(request, 'details_scan.html', {'infoMessage':infoMessages, 'status':getStatus(request), 'username':request.user, 'pk':host_id, 'booleanAdmin':booleanAdmin, 'form':newForm, 'general_information':general_information, 'services':services, 'notification':Notification('correct', 'Se ha modificado correctamente')})
        else:
            errors = []
            for error in form.errors:
                e = str(form.errors[error].as_text())
                e = e.replace("*", "")
                errors.append(e)
            message = 'Se han producido los siguientes errores: <br>' + ''.join("- "+str(error) + '<br>' for error in errors)
            return render(request, 'details_scan.html', {'infoMessage':infoMessages, 'status':getStatus(request), 'username':request.user, 'pk':host_id, 'booleanAdmin':booleanAdmin, 'form':newForm, 'general_information':general_information, 'services':services, 'notification':Notification('error', message)})
    
    form = ScanForm(initial={'identifier':host.identifier, 'notes':host.notes})
                
    return render(request, 'details_scan.html', {'infoMessage':infoMessages,'status':getStatus(request),'username':request.user, 'pk':host_id, 'booleanAdmin':booleanAdmin, 'form':form, 'general_information':general_information, 'services':services, 'json':information_dict})        
    
@login_required   
def details_scan_raw_data(request, host_id):
    booleanAdmin = is_shopyme_admin(request)
    if booleanAdmin:
        host = Host.objects.get(pk=host_id)
        information_dict = json.loads(host.data_json)
        return JsonResponse(information_dict)
    else:
        
        redirect('/scans/')

@login_required
def delete_service_scan(request, host_id):
    booleanAdmin = is_shopyme_admin(request)
    if booleanAdmin:
        host = Host.objects.get(pk=host_id)
        host.delete()
        syslog_message('Servicio eliminado por el usuario: '+str(request.user),'INFO')
        logPrintEvents('Servicio eliminado por el usuario: '+str(request.user))
        request.session['notification'] = 'Servicio eliminado correctamente'
        request.session['notification_type'] = 'correct'
        return redirect('/scans')

@login_required
def configuration(request, tab=None):
    adminUser = True if request.user.is_superuser else False
    if tab == None:
        tab == 'pass-change'
    
    if tab == "about":
        return render(request, 'configuration-about.html', {'infoMessage':infoMessages, 'username':request.user, 'status': getStatus(request), 'adminUser':adminUser})
    
    elif tab == "admin" and adminUser:
        return redirect('/admin')
    
    elif tab == "logout":
        return redirect('/logout')
    
    elif tab == "pass-change":
        form = ConfigChangePassForm()
        if request.method == 'POST':
            form = ConfigChangePassForm(request.POST)
            form['username'].value == request.user
            if form.is_valid():
                User.objects.filter(username=request.user).update(password=make_password(form['new_password'].value()))
                logPrintEvents('Contraseña modificada por el usuario: '+str(request.user))
                return redirect('/configuration/pass-change')
            else:
                errors = []
                for error in form.errors:
                    e = str(form.errors[error].as_text())
                    e = e.replace("*", "")
                    errors.append(e)
                message = 'Se han producido los siguientes errores: <br>' + ''.join("- "+str(error) + '<br>' for error in errors)
                return render(request, 'configuration-pass-change.html',{'infoMessage':infoMessages,'status':getStatus(request),'username':request.user,'form':form, 'notification':Notification('error', message),'adminUser':adminUser})
                
        else:
            return render(request, 'configuration-pass-change.html', {'infoMessage':infoMessages, 'username':request.user, 'status': getStatus(request), 'form':form, 'adminUser':adminUser})
    else:
        return redirect('/configuration/pass-change')

@login_required
def monitorization(request):
    booleanAdmin = is_shopyme_admin(request)
    alerts_get = AlertMonitorization.objects.all().order_by('pk')
    conf = Configuration.objects.first()
    
    
    alerts = []
    for a in alerts_get:
        alert = dict()
        alert['description'] = a.description
        alerts.append(alert)
    
    paginator = Paginator(alerts, 10)
    page = 1
    if 'page' in request.GET:
        page = int(request.GET.get('page'))
        
    if request.method == 'POST' and booleanAdmin:
        newForm = MonitorizationForm(request.POST)
        if newForm.is_valid():
            if ',' in newForm['ips'].value().strip():
                ips = newForm['ips'].value().strip().split(',')
            else:
                ips = newForm['ips'].value().strip()
            conf = Configuration.objects.first()
            alerts_api = api.alerts()
            for alert_api in alerts_api:
                api.delete_alert(alert_api['id'])
            
            if ',' in newForm['ips'].value().strip():
                for ip in ips:
                    api.create_alert('alerta - '+str(ip), str(ip)+"/32")
            else:
                api.create_alert('alerta - '+str(ips), str(ips)+"/32")
            
            conf.monitorization = newForm['monitorization_check'].value()
            if ',' in newForm['ips'].value().strip():
                conf.ips_monitorization = ','.join(i for i in ips)
            else:
                conf.ips_monitorization = ips
            conf.save()
            
            request.session['notification'] = 'Se ha establecido correctamente'
            request.session['notification_type'] = 'correct'
            
            restart_django(request)
            
        else:
            errors = []
            for error in newForm.errors:
                e = str(newForm.errors[error].as_text())
                e = e.replace("*", "")
                errors.append(e)
            message = 'Se han producido los siguientes errores: <br>' + ''.join("- "+str(error) + '<br>' for error in errors)
            return render(request, 'monitorization.html', {'infoMessage':infoMessages,'status':getStatus(request),'username':request.user,'alerts': paginator.get_page(page),'page':page , 'hasPrevious':paginator.page(page).has_previous(), 'hasNext':paginator.page(page).has_next(), 'notification':Notification('error', message), 'booleanAdmin':booleanAdmin, 'form':newForm})
    
    form = MonitorizationForm(initial={'monitorization_check':conf.monitorization, 'ips':conf.ips_monitorization})
    
    if request.session.get('notification') != None:
        notification = request.session.get('notification')
        notification_type = request.session.get('notification_type')
        request.session['notification'] = None
        request.session['notification_type'] = None
        return render(request, 'monitorization.html', {'notification':Notification(notification_type, notification), 'infoMessage':infoMessages,'status':getStatus(request),'username':request.user,'alerts': paginator.get_page(page),'page':page , 'hasPrevious':paginator.page(page).has_previous(), 'hasNext':paginator.page(page).has_next(), 'booleanAdmin':booleanAdmin, 'form':form})
    else:
        return render(request, 'monitorization.html', {'infoMessage':infoMessages,'status':getStatus(request),'username':request.user,'alerts': paginator.get_page(page),'page':page , 'hasPrevious':paginator.page(page).has_previous(), 'hasNext':paginator.page(page).has_next(), 'booleanAdmin':booleanAdmin, 'form':form})

@login_required  
def exportar_csv_services(request):
    booleanAdmin = is_shopyme_admin(request)
    if booleanAdmin:
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="datos_servicios.csv"'

        writer = csv.writer(response, delimiter='\t')
        writer.writerow(['Identificador', 'Datos_json', 'Notas'])  # Encabezados del CSV

        # Obtén todas las instancias de TuModelo y escribe los datos en el CSV
        for instancia in Host.objects.all():
            writer.writerow([instancia.identifier, instancia.data_json, instancia.notes])  # Agrega más campos según tu modelo

        return response
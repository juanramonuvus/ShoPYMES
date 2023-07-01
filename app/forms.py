from django import forms
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from app.models import CustomUser
from ipaddress import IPv4Address

class ShodanSearch(forms.Form):
    identifier = forms.CharField(widget=forms.HiddenInput(attrs={'value':'search'}))
    search = forms.CharField(label='Query', max_length=500, widget=forms.TextInput(attrs=
    {'class': 'form-input-search', 'placeholder': 'city:"Córdoba" country:"ES" city:"Villaviciosa de Córdoba"'}))
    
class ShodanSubmit(forms.Form):
    def __init__(self, options = None, *args, **kwargs):
        super(ShodanSubmit, self).__init__(*args, **kwargs)
        self.fields['asset'] = forms.MultipleChoiceField(required=False, label='Activo',choices=options, widget=forms.SelectMultiple(attrs=
        {'class': 'form-input create backup','size':'10'}))
        self.fields['identifier'] = forms.CharField(widget=forms.HiddenInput(attrs={'value':'submit'}))
    identifier = forms.CharField(widget=forms.HiddenInput(attrs={'value':'submit'}))
    asset = forms.MultipleChoiceField()

class LoginForm(forms.Form):
    username = forms.CharField(label='Username', max_length=100,widget=forms.TextInput(attrs=
    {'class': 'form-input login-form','placeholder': 'Usuario'}))
    password = forms.CharField(label='Password', max_length=100,widget=forms.TextInput(attrs=
    {'class': 'form-input login-form','placeholder': 'Contraseña','type':'password'}))

class ScanForm(forms.Form):
    identifier = forms.CharField(required=False, label='Identificador', widget=forms.TextInput(attrs=
    {'class':'form-input create'}))
    notes = forms.CharField(label='Notas', max_length=100, required=False, widget=forms.TextInput(attrs=
    {'class': 'form-input create','placeholder':'Cualquier nota que quiera añadir sobre el activo'}))
    
    def clean(self):
        super().clean()
        identifier = self.cleaned_data.get('identifier')
        ## Check fields
        if len(identifier) <= 3:
            self.add_error('identifer', 'El identificador debe tener más de 3 caracteres')
            
class MonitorizationForm(forms.Form):
    monitorization_check = forms.BooleanField(required=False, widget=forms.CheckboxInput())
    ips = ipv4_interval = forms.CharField(required=False, label='IPs', max_length=5000,widget=forms.TextInput(attrs=
    {'class': 'form-input create','placeholder': 'Ej: 192.168.20.15,192.168.20.16,192.168.20.20'}))    
    
    def clean(self):
        form_data = super().clean()
        monitorization_check = form_data['monitorization_check']
        ips = form_data['ips']
        
        if monitorization_check == True and len(ips) == 0:
            self.add_error('monitorization_check','No puedes marcar la casilla si no has establecido ninguna ip.')
        
        
        elif len(ips) != 0 and ',' in ips.strip():
            ips_res = [i.strip() for i in ips.split(",")]
            for ip in ips_res:
                try:
                    ip_check = IPv4Address(ip)
                except:
                    self.add_error('ips', 'Una de las ips no es valida.')
                    
        elif len(ips) != 0 and ',' not in ips.strip():
            try:
                ip_check = IPv4Address(ips)
            except:
                self.add_error('ips', 'La Ip no cumple el formato.')
        
    
class ConfigChangePassForm(forms.Form):
    username = forms.CharField(required=False, label='Usuario', widget=forms.TextInput(attrs=
    {'class': 'form-input create','type':'hidden'}))
    old_password = forms.CharField(label='Contraseña actual', max_length=100,widget=forms.TextInput(attrs=
    {'class': 'form-input create','type':'password'}))
    new_password = forms.CharField(label='Nueva contraseña', max_length=100,widget=forms.TextInput(attrs=
    {'class': 'form-input create','type':'password'}))
    new_password2 = forms.CharField(label='Repetir nueva contraseña', max_length=100,widget=forms.TextInput(attrs=
    {'class': 'form-input create','type':'password'}))

    def clean(self):
        form_data = self.cleaned_data
        if User.objects.filter(username=form_data['username']).exists():
            pass_store = User.objects.get(username=form_data['username']).password
            if check_password(form_data['old_password'], pass_store):
                if form_data['new_password'] == form_data['new_password2']:
                    return True
                else:
                    self.add_error('new_password2', 'Las contraseñas nuevas no coinciden entre si')
            else:
                self.add_error('old_password', 'La contraseña actual no es correcta')
        else:
            self.add_error('username', 'El usuario no existe')
            
        return form_data
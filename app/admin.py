from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User

# Register your models here.
from .models import Event, Host, Vulnerability, CustomUser

admin.site.register(Event)
admin.site.register(Host)
admin.site.register(Vulnerability)

class CustomUserInLine(admin.StackedInline):
    model = CustomUser
    can_delete = False
    verbose_name_plural = "customuser"
    
class UserAdmin(BaseUserAdmin):
    inlines = [CustomUserInLine]
    
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

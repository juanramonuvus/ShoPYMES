from django.contrib.auth.models import User
from django.db import models

# Create your models here.
class Host(models.Model):
    data_json = models.JSONField(blank=True)
    identifier = models.CharField(blank=True, null=True, max_length=100)
    notes = models.CharField(max_length=200, blank=True, null=True)
    
    def __str__(self):
        return self.data_json
    
class Vulnerability(models.Model):
    identifier = models.CharField(max_length=100, primary_key=True, unique=True)
    description = models.CharField(max_length=800, blank=True, null=True)
    
    def __str__(self):
        return 'identifier: '+self.identifier
    
class Event(models.Model):
    description = models.CharField(max_length=100)
    date = models.DateTimeField()
    
    def __str__(self):
        return self.description + '\n\n' + str(self.date)

    def save(self, *args, **kwargs):
        if Event.objects.count() > 100000:
            for event in Event.objects.all().order_by('pk').reverse()[99999:]:
                event.delete()
        super(Event, self).save(*args, **kwargs)
        
class CustomUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    shopyme = models.BooleanField(default=False)
        
        
class Configuration(models.Model):
    monitorization = models.BooleanField(default=False)
    ips_monitorization = models.CharField(max_length=800, blank=True, null=True, default='')
    
        
class AlertMonitorization(models.Model):
    description = models.CharField(max_length=800, blank=True, null=True)
    
    def __str__(self):
        return self.description

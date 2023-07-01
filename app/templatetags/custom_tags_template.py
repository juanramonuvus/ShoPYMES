from django import template
from django.utils.safestring import mark_safe
from django.forms.widgets import CheckboxInput
from django.forms import RadioSelect, TypedChoiceField
from app.utils import is_shopyme_admin

register = template.Library()

@register.simple_tag
def readonly_form(form, request):
    res = is_shopyme_admin(request)
    if res == False:
        for field in form:
            field.field.widget.attrs['disabled'] = True
            field.field.widget.attrs['readonly'] = True
            field.field.widget.attrs['style'] = 'background-color: #ffffff; color: #000000;'
                
    return mark_safe('')

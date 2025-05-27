from django.urls import path
from ondc.views import  on_subscribe

urlpatterns = [
    path('on_subscribe', on_subscribe, name='on_subscribe'),
]
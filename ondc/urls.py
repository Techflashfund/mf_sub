from django.urls import path
from ondc.views import  *

urlpatterns = [
    path('on_subscribe', on_subscribe, name='on_subscribe'),
    path('subscribe',subscribe, name='subscribe'),

]
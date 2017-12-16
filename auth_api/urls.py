from django.conf.urls import url, include
from auth_api.views import UserLoginView



urlpatterns = [
    url(r'^login/$', UserLoginView.as_view(), name='rest_login'),
    #url(r'^logout/$', LogoutView.as_view(), name='rest_logout'),
]

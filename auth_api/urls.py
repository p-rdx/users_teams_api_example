from django.conf.urls import url, include
from auth_api import views



urlpatterns = [
    url(r'^login/$', views.UserLoginView.as_view(), name='rest_login'),
    url(r'^logout/$', views.UserLogoutView.as_view(), name='rest_logout'),
    url(r'^whoami/$', views.WhoamiView.as_view()),
]

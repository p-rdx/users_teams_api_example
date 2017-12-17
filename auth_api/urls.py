from django.conf.urls import url, include
from auth_api import views



urlpatterns = [
    url(r'^login/$', views.UserLoginView.as_view(), name='rest_login'),
    url(r'^logout/$', views.UserLogoutView.as_view(), name='rest_logout'),
    url(r'^whoami/$', views.WhoamiView.as_view()),
    url(r'^reset/$', views.PasswordResetInitView.as_view()),
    url(r'^password/$', views.PasswordResetView.as_view()),
    url(r'^invite/$', views.MakeInvitationLink.as_view()),
    url(r'^register/$', views.RegisterView.as_view())
]

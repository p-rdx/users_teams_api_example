from django.conf.urls import url, include
from django.conf import settings
from auth_api import views
from rest_framework.documentation import include_docs_urls



urlpatterns = [
    url(r'^login/$', views.UserLoginView.as_view(), name='login'),
    url(r'^logout/$', views.UserLogoutView.as_view(), name='logout'),
    url(r'^userdetails/$', views.UserDetailsView.as_view(), name='user details'),
    url(r'^reset/$', views.PasswordResetInitView.as_view(), name='reset password'),
    url(r'^password/$', views.PasswordResetView.as_view(), name = 'set password'),
    url(r'^invite/$', views.InvitePerson.as_view(), name='invite'),
    url(r'^register/$', views.RegisterView.as_view(), name='register'),
    url(r'^create_team/$', views.CreateTeamView.as_view(), name='create_team'),
    url(r'^verify_email/$', views.VerifyEmailView.as_view(), name='verify_email'),
    url(r'^$', views.APIRoot.as_view(), name='api root'),

    
]

if settings.DEBUG:
    urlpatterns += [
        url(r'^retrieve_code/$', views.RetrieveCodesView.as_view(), name='get codes'), 
    ]
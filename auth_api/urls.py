from django.conf.urls import url, include
from django.conf import settings
from auth_api import views
from rest_framework.documentation import include_docs_urls



urlpatterns = [
    url(r'^login/$', views.UserLoginView.as_view()),
    url(r'^logout/$', views.UserLogoutView.as_view()),
    url(r'^userdetails/$', views.UserDetailsView.as_view()),
    url(r'^reset/$', views.PasswordResetInitView.as_view()),
    url(r'^password/$', views.PasswordResetView.as_view()),
    url(r'^invite/$', views.MakeInvitationLink.as_view()),
    url(r'^register/$', views.RegisterView.as_view()),
    url(r'^create_team/$', views.CreateTeamView.as_view()),
    url(r'^verify_email/$', views.VerifyEmailView.as_view()),
    url(r'^$', views.APIRoot.as_view()),

    
]

if settings.DEBUG:
    urlpatterns += [
        url(r'^retrieve_code/$', views.RetrieveCodesView.as_view()), 
    ]
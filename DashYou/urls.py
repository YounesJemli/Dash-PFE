"""
URL configuration for DashYou project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from DashYouApp import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('admin/', admin.site.urls),
    path('',views.authentication,name='authentication'),
    path('developper/', views.developper, name='developper'),
    path('update-profile/', views.update_profile, name='update_profile'),
    path('update-password/', views.update_password, name='update_password'),
    path('pipeline/', views.pipeline_page, name='pipeline_page'),
    path('supervisor/', views.supervisor, name='supervisor'),
    path('adminpage/', views.adminpage, name='adminpage'),
    path('update-profilepip/', views.update_profilepip, name='update_profilepip'),
    path('update-passwordpip/', views.update_passwordpip, name='update_passwordpip'),
    path('pipeline/<str:pipeline_name>/', views.jenkins_build_logs, name='jenkins_build_logs'),
    path('logout/', views.user_logout, name='logout'),
       ] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

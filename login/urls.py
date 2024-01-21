from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from . import views
from .views import download_static_file

urlpatterns = [
    path('', views.Login, name='login'),
    path('Login_view', views.Login_view),
    path('dashboard/', views.dashboard, name='dashboard/'),
    # path('dashboard/', views.Login_view, name='dashboard/'),
    path('dashboard/add_host_to_monitoring', views.combine,
         name='add_host_to_monitoring'),
    path('dashboard/host_bulk_import', views.host_bulk_import,
         name='host_bulk_import'),
    path('dashboard/remove_host_from_monitoring', views.remove_host_from_monitoring,
         name='remove_host_from_monitoring'),
    path('dashboard/add_host_to_maintenance',
         views.add_host_to_maintenance, name='add_host_to_maintenance'),
    path('dashboard/remove_host_from_maintenance', views.remove_host_from_maintenance,
         name='remove_host_from_maintenance'),
    path('dashboard/add_user_to_console',
         views.add_user_to_console, name='add_user_to_console'),
    path('dashboard/remove_user_from_console',
         views.remove_user_from_console, name='remove_user_from_console'),
    path('dashboard/add_host_to_monitoring_form',
         views.add_host_to_monitoring_form),
    path('dashboard/remove_host_from_monitoring_form',
         views.remove_host_from_monitoring_form),
    path('dashboard/add_host_to_maintenance_form',
         views.add_host_to_maintenance_form),
    path('dashboard/remove_host_from_maintenance_form',
         views.remove_host_from_maintenance_form),
    path('dashboard/add_user_to_console_form',
         views.add_user_to_console_form),
    path('dashboard/remove_user_from_console_form',
         views.remove_user_from_console_form),
    #     path('dashboard/add_host_to_monitoring/',
    #          views.my_view),
    path('download/<path:file_path>/',
         download_static_file, name='download_static_file'),
    path('dashboard/bulk_import_host_form',
         views.bulk_import_host_form),



]

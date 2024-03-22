
from django.contrib import admin
from django.urls import path,include
from rest_framework.authtoken import views
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView
from schema_graph.views import Schema
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # this refresh url is used for refreshing the expired access token 
    path("schema/",Schema.as_view()),
    path(r"^schema/$",Schema.as_view()),
    
    path("apiWork/",include("accounts.urls"))
]

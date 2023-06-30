from django.urls import path, include

from rest_framework import routers

from predictor_app import views

#Routes
router = routers.DefaultRouter()
router.register(r'spam-detector', views.SpamDetectorViewSet, basename='spam-detector')

urlpatterns = [
    path('', include(router.urls))
]

from django.urls import path
from Dashboard import views

urlpatterns = [
    path('index/',views.index,name="index"),
    path('Register/',views.Register,name="Register"),
    path('createuser/',views.createuser,name="createuser"),
    path('viewuser/',views.viewuser,name="viewuser"),
    path('deleteuser/<int:dlt>/',views.deleteuser,name="deleteuser"),
    path('viewproduct/',views.viewproduct,name="viewproduct"),
    path('addcategory/',views.addcategory,name="addcategory"),
    path('addproduct/',views.addproduct,name="addproduct"),
    path('saveproduct/',views.saveproduct,name="saveproduct"),
    path('editproduct/<int:dataid>/',views.editproduct,name="editproduct"),
    path('updateproduct/<int:dataid>/',views.updateproduct,name="updateproduct"),
    path('deleteproduct/<int:delpro>/',views.deleteproduct,name="deleteproduct"),
    path('saveuser/',views.saveuser,name="saveuser"),
]
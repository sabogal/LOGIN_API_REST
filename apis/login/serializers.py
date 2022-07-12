
from rest_framework import serializers
from apis.login.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    pass

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','password','username','email','name','last_name','groups','is_superuser', 'intentos']
        
    def create(self,validated_data):
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user
    
class ChangePasswordSerializer(serializers.Serializer):
    model = User
    #old_password = serializers.CharField(required = True)
    new_password = serializers.CharField(required = True, write_only = True)
  
 


#------------------------------Dependencias para Correo de recuperacion---------------------------#

from email.mime.multipart import MIMEMultipart
from sre_parse import State
import uuid
from django.template.loader import render_to_string
from email.mime.text import MIMEText
import smtplib
from proyecto_Dagma import settings

#--------------------------------Dependencias para registro de usuario----------------------------#

from rest_framework import status
from rest_framework.response import Response
from rest_framework import viewsets, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics

#---------------------------------------------LOGOUT-----------------------------------------------#

from rest_framework.generics import GenericAPIView
from rest_framework_simplejwt.tokens import RefreshToken

#----------------------------------------------EXPIRED---------------------------------------------#

from django.http import HttpResponseRedirect
from datetime import datetime


#---------------------------------------------GENERAL----------------------------------------------#

from apis.login.models import User
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import UserSerializer
from .serializers import CustomTokenObtainPairSerializer,ChangePasswordSerializer
from django.contrib.auth import authenticate
from requests import request



# - - - - - - - - - - - - - - - - - - - - - - - VIEWS - - - - - - - - - - - -  - - - - - - - - #

#-----------------------------------Vista principal de /user/----------------------------------#

class userViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    queryset = User.objects.all()

#------------------------------------Correo de recuperacion------------------------------------#

class Recovery_password(GenericAPIView):
    
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]

    def send_email_reset_pwd(self, user): 
        data = {}
        try:
            
            URL = settings.DOMAIN if not settings.DEBUG else self.request.META['HTTP_HOST']
            user.token = uuid.uuid4
            user.save()
            
            mailServer = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
            mailServer.ehlo()
            mailServer.starttls()
            mailServer.ehlo()
            mailServer.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
            
            #construimos el mensaje simple
            email_to = user.email 
            mensaje = MIMEMultipart()
            mensaje['From'] = settings.EMAIL_HOST_USER
            mensaje['To'] = email_to
            mensaje['Subject'] = 'Reseteo de contraseña'
            
            content = render_to_string('send_email.html', {
                'user': user,
                'link_resetpwd': 'http://{}/change/password/{}/'.format(URL, str(user.token)),
                'link_home': 'http://{}'.format(URL)
            })
            mensaje.attach(MIMEText(content, 'html'))
            
            # Envio del mensaje
            mailServer.sendmail(settings.EMAIL_HOST_USER,email_to,mensaje.as_string())

        except Exception as e:
            data['error'] = str(e)
            print("No sirvio")
        return data

    def post(self, request, *args, **kwargs):
        print(request.data['email'])
        try:
            user = User.objects.get(email=request.data['email'])
            self.send_email_reset_pwd(user)
            return Response({'message' : 'Se ha enviado email'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': 'email no enviado'}, status=status.HTTP_400_BAD_REQUEST)
        
#-------------------------------------Vista principal para registro---------------------------------#

class UserRegisterAPIView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "El usuario ha sido creado exitosamente"},status=status.HTTP_200_OK)
        return Response({'message':"Ha ocurrido un error al crear el usuario"}, status=status.HTTP_400_BAD_REQUEST)

#----------------------------------------------LOGIN--------------------------------------------#

class Login(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        username = request.data.get('username', '')
        password = request.data.get('password', '')
        user = authenticate(
            username=username,
            password=password
        )
        user_intento = User.objects.get(username=request.data['username'])
        #user_state = User.objects.get()
        print(request.data.get('is_active'))
        login_serializer = self.serializer_class(data=request.data)

        if User.is_active == "false":
            return Response({'error': 'La cuenta esta desactivada' }, status = status.HTTP_404_NOT_FOUND)
            # if user:
            #     if login_serializer.is_valid():
            #         user_serializer = UserSerializer(user)
            #         return Response({
            #             'token': login_serializer.validated_data.get('access'),
            #             'refresh-token': login_serializer.validated_data.get('refresh'),
            #             'user': user_serializer.data,
            #             'message': 'Inicio De Sesion Exitosa'
            #         },status = status.HTTP_200_OK)
            #     else:
                    
            #         return Response({'error': 'Contraseña o Nombre De Usuario Incorrectos'}, status = status.HTTP_400_BAD_REQUEST)
                
            
            # return Response({'error': 'Querido admin, Contraseña errada' }, status = status.HTTP_404_NOT_FOUND)
        else:
            if user_intento.intentos <= 3:
                if user:
                    if user_intento.intentos <= 3 :
                        if login_serializer.is_valid():
                            user_serializer = UserSerializer(user)
                            return Response({
                                'token': login_serializer.validated_data.get('access'),
                                'refresh-token': login_serializer.validated_data.get('refresh'),
                                'user': user_serializer.data,
                                'message': 'Inicio De Sesion Exitosa'
                            },status = status.HTTP_200_OK)           
                    return Response({'error': 'Demasiados intentos'}, status = status.HTTP_400_BAD_REQUEST)
                #return Response({'error': 'Ha ocurrido un error'}, status = status.HTTP_400_BAD_REQUEST)
                myIntentos = user_intento.intentos + 1
                intentosRestantes = 3 - user_intento.intentos
                User.objects.filter(username=user_intento).update(intentos=myIntentos)
                return Response({'error': 'Contraseña no valido', 'intentos_restante': intentosRestantes   }, status = status.HTTP_400_BAD_REQUEST)
            return Response({'error': 'Demasiados intentos sapoperro'}, status = status.HTTP_400_BAD_REQUEST)

                  
                    
            # if user:
            #     if user_intento.intentos >= 3:
            #         return Response({'error': 'Muchos intentos'}, status = status.HTTP_400_BAD_REQUEST)
                
            #     else: 
            #         if login_serializer.is_valid():
            #             user_serializer = UserSerializer(user)
            #             return Response({
            #                 'token': login_serializer.validated_data.get('access'),
            #                 'refresh-token': login_serializer.validated_data.get('refresh'),
            #                 'user': user_serializer.data,
            #                 'message': 'Inicio De Sesion Exitosa'
            #             },status = status.HTTP_200_OK)
                        
            # else:
            #     myIntentos = user_intento.intentos + 1
            #     intentosRestantes = 0 + user_intento.intentos
            #     User.objects.filter(username=user_intento).update(intentos=myIntentos)
            #     return Response({'error': 'Contraseña o usuario no valido', 'intentos_restante': intentosRestantes   }, status = status.HTTP_400_BAD_REQUEST)
                        
                    
                

#------------------------------------------------LOGOUT-----------------------------------------------#

class Logout(GenericAPIView):
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        user = User.objects.filter(id=request.data.get('user', 0))
        if user.exists():
            RefreshToken.for_user(user.first())
            return Response({'message': 'Sesión cerrada correctamente.'}, status=status.HTTP_200_OK)
        return Response({'error': 'No existe este usuario.'}, status=status.HTTP_400_BAD_REQUEST)

#------------------------------------------------AFK------------------------------------------------#

#------------------------------------------------Password------------------------------------------------#
class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # if not self.object.check_password(serializer.data.get("old_password")):
            #      return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            return Response({'message': 'Contraseña correctamente cambiada'}, status = status.HTTP_200_OK)
        return Response({'error':'Ha ocurrido un error al cambiar la contraseña'}, status=status.HTTP_400_BAD_REQUEST)


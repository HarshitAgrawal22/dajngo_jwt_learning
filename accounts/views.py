from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from accounts.serializers import *
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework.permissions import IsAuthenticated


def get_tokens(user)->dict:# this is the method for getting  tokens for a user to autherize
    refresh=RefreshToken.for_user(user)# this built in will provide us both access and refresh token 
    return {
        "refresh":str(refresh),
        "access":str(refresh.access_token)
    }# got both the tokens 
    
    
    
class UserRegistrationView(APIView):
    def get(self,request):
        return Response({"user":User.objects.get(pk=request.data.get("id")).username})
    # this code will be executed when we hit the url with the get request 
    # and it will provide us the id in the body of the request 
    # if the user with that id is found then it will return the username else it will raise a exception 
    # it can be done by just checking if the user is none
    
    
    def  post(self, request):
        serializer=UserRegistrationSerializers(data=request.data)
        if serializer.is_valid():
            # checking if the serializer is valid or not 
            # it is being checked by the validate method in the serializer we are using 
            user=serializer.save() # it will save and return the user created by the serialized data
            return Response({
            "msg":"regestrationsucessfull",                
            "data":serializer.data,# here we are getting the data from the serializer which it is holding
            
            "tokens":get_tokens(user)
            # here we are using the method we created at the top for getting  the access and refresh token for the user 
                     },status=status.HTTP_201_CREATED
                            )
        
        
        
        
        return Response({"msg":serializer.errors},status=status.HTTP_400_BAD_REQUEST)#if any exception occurs it will show the exception to us by the this but in json format so it doesnt break the flow of the code
    # this post reuest will be hit when we hit the api with a post request
    # this is used while registering a new user 
    


class UserLoginView(APIView):
    renderer_classes=[UserRenderer]
    # these render  classes provide us the format to show the exception in the json of the api 
    
    def post(self, request):# this is login post reuest api 
        serializer = UserLoginSerializer(data=request.data) 
        # using the custom defined serializer by sending it the data(body and headers) of the request
        if serializer.is_valid():
            # checking if the data provided by the request is valid or not by the validate method defined in the serializers
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            
            # these are the data we are getting after validating it 
            user = authenticate(username=username, password=password)
            # normally authenticating the user by the authenticate method 
            if user is not None:
                return Response({"tokens":get_tokens(user)}, status=status.HTTP_200_OK)
            # if the user is not none then we are gettings its token and adding it to our response
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
            
            # here this will be used when there is a credential fault
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # return Response({"msg":"either the password or username is incorrect","errorss":""},status=status.HTTP_404_NOT_FOUND)


class UserProfileView(APIView):
    # this method will be used to view the profile of the User
    renderer_classes=[UserRenderer]
     # the custom defined render class (will come handy if any exception occurs)
    permission_classes=[IsAuthenticated]
    # this will check if the user is authenticated or not by checking the access token in the headers
    # but it needs the latest token from the headers
    # as the token expires
    def get(self,request):
        serializer=UserProfileSerializer(request.user)
        # in it we are sending the access token in the headers of the api
        # format is
        # Accept application/json
        #Bearer token
        
        # the code below explains the format of the api request will be made
        return Response(serializer.data,status=status.HTTP_200_OK)
  #  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzA4NDY3NjkwLCJpYXQiOjE3MDg0NjQwOTAsImp0aSI6ImI0YjBlNTZlYThjMjQyNDc4MWEzOGNiMWM4ODgzZjZiIiwidXNlcl9pZCI6MTB9.xIS0u5uj1B1iMMIcXd_zj1YT97AvIvBCgo03YwsoUM8
   # this is the format in the headers for the authentication  
     
            
#     import 'dart:convert';
# import 'package:http/http.dart' as http;

# Future<Map<String, dynamic>> getUserProfile(String token) async {
#   final response = await http.get(
#     Uri.parse('$_baseUrl/profile'),
#     headers: <String, String>{
#       'Content-Type': 'application/json; charset=UTF-8',
#       'Authorization': 'Bearer $token',
#     },
#   );

#   if (response.statusCode == 200) {
#     return json.decode(response.body);
#   } else {
#     throw Exception('Failed to load user profile');
#   }
# }



class UserChangePasswordView(APIView):
    renderer_classes=[UserRenderer]
    # render classes for displaying exception if it occurs 
    permission_classes=[IsAuthenticated]
    # this is to authenticate the user by the access token 
    def post(self,request):
        serializer=UserChangePasswordSerializer(
            # the data from the request is sent by the data 
            data=request.data,
            context={
                      "user":request.user
                      
                    }
            # the extra data which have to be sent is sent by the context method to the serializer 
            # we have authenticated the user by token 
            # so the user is stored in the request and we have acces it directly from the request to end it to serializer in context
            )
        # whenever we have to send data rather than request we use context
        if serializer.is_valid(raise_exception=True):
            # validating serializer by validate method of the serializer
            return Response({"msg":"change password"},status=status.HTTP_200_OK)
        
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)





class SendPasswordResetEmailView(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request):
        serializer=SendPasswordResetEmailSerializer(data=request.data)
        # will activate the serializer
        if(serializer.is_valid(raise_exception=True)):
            return Response({"msg":"the email has been sent please  check your inbox"},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_404_NOT_FOUND)
    
    
    
    
class UserPasswordResetView(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request,uid,token):
        print(uid , token)
        serializer=UserPasswordResetSerializer(data=request.data,context={"uid":uid,"token":token})
        if serializer.is_valid():
            return  Response({"msg":"password updated"},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)    
        
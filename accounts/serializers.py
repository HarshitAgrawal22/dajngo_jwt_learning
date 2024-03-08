from rest_framework import serializers
from django.contrib.auth.models import User
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode

from accounts.utils import Util



class UserRegistrationSerializers(serializers.ModelSerializer):
    # we are writing this code because we need to confirm trhe password field in our regestration request
    password= serializers.CharField(style={'input_type':'password'},write_only=True)
    # these are the fields need while registering the user
    class Meta:
        model=User
        # defining the model for the serializer
        fields=["username","password","email","is_staff"]
        # these are the fields which will be displayed in the serialized data
 
        extra_kwargs={
            'password':{'write_only':True}
            
            }
    def validate(self,attrs):
        # if attrs.get("password")!=attrs.get("password1"):
        #     raise serializers.ValidationError('both the paswords doesnt match')
        
        return attrs
        # this validate function is used of checkin a condition needed while creating a new user 
        # the condition  can be like the age of the user must be more than 0 
        

    def create(self, validated_data):
        user=User.objects.create(username=validated_data.get("username"),email=validated_data.get("email"))
        user.set_password(validated_data.get("password"))
        user.save()
        return user
    # this method is used when we are creating the new user 
    
    
class UserLoginSerializer(serializers.ModelSerializer):
    
    # def validate(self,attrs):
    #     return attrs
    username = serializers.CharField()# defines incoming data will be string 
    password = serializers.CharField(style={'input_type': 'password'})
    # these fields(username and password) are the fields which must be in the request body
    class Meta:
        model=User
        # defining the model for the serializer
        fields=["username","password"]
        # fields to display
        
        
        
        
        
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        # defining the model for the serializer
        fields=["id","email","username","is_staff"]# fields to display



class UserChangePasswordSerializer(serializers.ModelSerializer):
    password=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)# this is the field we are going take as input 
    
    class Meta:
        model=User
        # defining the model for the serializer
        fields=['password']# fields to display
    def validate(self, attrs):
        user=self.context.get("user")
        password=attrs.get("password")
        if password is not None:
            user.set_password(password)
            user.save()
            return attrs
        else :  raise serializers.ValidationError('the passowrd in none')
    
     # this validate function is used for checking a condition needed while creating a new user 
        # the condition  can be like the age of the user must be more than 0 
        
    
    
    
    
    
    
    
class SendPasswordResetEmailSerializer(serializers.Serializer):
    username=serializers.CharField(max_length=255)
    class Meta:
        fields=["username"]# fields to display
    def validate(self, attrs):
        username=attrs.get("username")
        if  User.objects.filter(username=username).exists():
            user=User.objects.get(username=username)
            
            uid=urlsafe_base64_encode(force_bytes(user.pk))
            token=PasswordResetTokenGenerator().make_token(user)
            link="http://localhost:8000/apiWork/reset-password/"+uid+"/"+token
            print(link)
            Util.send_mail({
                "subject":"reset your password",
                "to_email":"haharshit22@gmail.com",
                "body":"Click the following link   "+link
            })
            return attrs
        else:
            raise  serializers.ValidationError('User isnot registered')

 # this validate function is used of checkin a condition needed while creating a new user 
        # the condition  can be like the age of the user must be more than 0 
        



class UserPasswordResetSerializer(serializers.Serializer):
    
    password=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)# this is the field we are going take as input 
    
    class Meta:
        model=User
        # defining the model for the serializer
        fields=['password']# fields to display
    def validate(self, attrs):
        password=attrs.get("password")
        uid=self.context.get("uid")
        token=self.context.get("token")
        print(uid,token,password)
        try:
            if password is not None:
                id=smart_str( urlsafe_base64_decode(uid))
                user= User.objects.get(id=id)
                if not PasswordResetTokenGenerator().check_token(user,token):
                    raise serializers.ValidationError('Token is not valid')
                # the exceptions we are raising all the code are being handled by the django builtin exception handler
                print(user,"lololololololololol")
                user.set_password(password)
                user.save()
                return attrs
            else :  raise serializers.ValidationError('the passowrd in none')
        except DjangoUnicodeDecodeError:
            raise  serializers.ValidationError('the token is expired or not valid') # this validate function is used of checkin a condition needed while creating a new user 
        # the condition  can be like the age of the user must be more than 0 
        
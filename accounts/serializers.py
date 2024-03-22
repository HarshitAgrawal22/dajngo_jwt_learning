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
#     For JWT token registration, you might use the create() method to perform tasks such as:

# Validating the incoming data: Ensure that the data provided in the registration request is valid before creating a new user.

# Creating a new user object: Create a new user instance based on the validated data from the request.

# Generating JWT tokens: After creating the user, generate JWT tokens (access token and refresh token) and include them in the response.

# Additional processing: Perform any additional processing or tasks required for registration, such as sending a confirmation email, logging events, etc.
    
    
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
    # the username will be the thing we will be asking for 
    class Meta:
        fields=["username"]# fields to display
    def validate(self, attrs):
        username=attrs.get("username")
        # we will get it from the incoming request.data
        if  User.objects.filter(username=username).exists():
            
            user=User.objects.get(username=username)
            
            uid=urlsafe_base64_encode(force_bytes(user.pk))
            # encoding the user's id to be able to sent by the link 
            
            token=PasswordResetTokenGenerator().make_token(user)
            # genrating token for user 
            link="http://localhost:8000/apiWork/reset-password/"+uid+"/"+token
            print(link)
             # the link will be through the email 
             #TODO: make email thing work 
            Util.send_new_mail({
                "subject":"reset your password",
                "to_email":"haharshit22@gmail.com",
                "body":"Click the following link   "+link
            })
            # return attrs
            return attrs
        else:
            raise  serializers.ValidationError('User isnot registered')

 # this validate function is used of checkin a condition needed while creating a new user 
        # the condition  can be like the age of the user must be more than 0 
        



class UserPasswordResetSerializer(serializers.Serializer):
    # this serializer is pinged by the reset email
    password=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)# this is the field we are going take as input 
    
    
    class Meta:
        model=User
        # defining the model for the serializer
        fields=['password']# fields to display
    def validate(self, attrs):
        password=attrs.get("password")
        uid=self.context.get("uid")
        token=self.context.get("token")
        # we are getting these fields from request data and database
    
        print(uid,token,password)
        try:
            if password is not None:
                id=smart_str( urlsafe_base64_decode(uid))
                # decoding the id we get through the send email 
                user= User.objects.get(id=id)
                
                if not PasswordResetTokenGenerator().check_token(user,token):
                    raise serializers.ValidationError('Token is not valid')
                # the exceptions we are raising all the code are being handled by the django builtin exception handler
                print(user)
                user.set_password(password)
                user.save()
                return attrs
            else :  raise serializers.ValidationError('the passowrd in none')
        except DjangoUnicodeDecodeError:
            raise  serializers.ValidationError('the token is expired or not valid') # this validate function is used of checkin a condition needed while creating a new user 
        # the condition  can be like the age of the user must be more than 0 
        
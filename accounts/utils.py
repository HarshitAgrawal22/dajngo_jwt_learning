from  django.core.mail import send_mail

import os 
class Util:
    @staticmethod
    def send_new_mail(data):
        send_mail(
            subject=data["subject"],
            message=data["body"],
            from_email='test22032005@gmail.com',
            recipient_list=["haharshit22@gmail.com",]
            
        )
        
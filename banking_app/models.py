from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data["id"]
        self.email = user_data["email"]
        self.username = user_data["username"]
        self.first_name = user_data["first_name"]
        self.last_name = user_data["last_name"]

        self.phone = user_data["phone"]
        self.address = user_data["address"]
        self.date_of_birth = user_data["date_of_birth"]


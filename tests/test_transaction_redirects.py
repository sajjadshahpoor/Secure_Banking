import unittest

from flask_login import login_user

from banking_app.app import create_app
from banking_app.models import User


class DummyUser(User):
    def __init__(self):
        super().__init__(
            {
                "id": "test-user",
                "email": "test@example.com",
                "username": "testuser",
                "first_name": "Test",
                "last_name": "User",
                "phone": None,
                "address": None,
                "date_of_birth": None,
            }
        )


class TransactionRedirectTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()

    def test_transfer_post_redirects_to_dashboard(self):
        with self.client.session_transaction() as session:
            session["_user_id"] = "test-user"
            session["logged_in"] = True

        self.client.application.login_manager._load_user = lambda *args, **kwargs: DummyUser()

        response = self.client.post(
            "/transfer",
            data={
                "from_account": "Checking",
                "account_number": "BE1234567890",
                "recipient": "Jane",
                "amount": "50",
                "description": "Test transfer",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")

    def test_deposit_post_redirects_to_dashboard(self):
        with self.client.session_transaction() as session:
            session["_user_id"] = "test-user"
            session["logged_in"] = True

        self.client.application.login_manager._load_user = lambda *args, **kwargs: DummyUser()

        response = self.client.post(
            "/deposit",
            data={
                "amount": "75",
                "description": "Test deposit",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")


if __name__ == "__main__":
    unittest.main()

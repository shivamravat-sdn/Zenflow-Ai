from django.test import TestCase, SimpleTestCase
from rest_framework.test import APIClient
from rest_framework import status
from authentication.models import Users

# Create your tests here.

class UserAuthenticationTests(SimpleTestCase):
    def setUp(self):
        self.client = APIClient()

    def test_user_registration_success(self):
        response = self.client.post('/register/', {
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'testuser@example.com',
            'password': 'testpassword123'
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_user_login_success(self):
        Users.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpassword123'
        )
        response = self.client.post('/login/', {
            'email': 'testuser@example.com',
            'password': 'testpassword123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_user_update_success(self):
        user = Users.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpassword123'
        )
        response = self.client.put(f'/update/{user.id}/', {
            'first_name': 'Updated',
            'last_name': 'User'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_user_registration_invalid_data(self):
        response = self.client.post('/register/', {
            'username': '',
            'email': 'invalidemail',
            'password': 'short'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_login_invalid_credentials(self):
        response = self.client.post('/login/', {
            'email': 'nonexistent@example.com',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_update_non_existent_user(self):
        response = self.client.put('/update/999/', {
            'first_name': 'NonExistent',
            'last_name': 'User'
        })
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
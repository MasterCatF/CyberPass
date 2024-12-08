import unittest
import os
import sqlite3
from CyberPass import Database, LoginApp  # Asegúrate de que LoginApp esté importado

class TestDatabase(unittest.TestCase):

    def setUp(self):
        """Configurar la base de datos de prueba."""
        self.test_db = 'test_users.db'  # Base de datos de prueba
        self.db = Database()
        self.db.connection = sqlite3.connect(self.test_db)
        self.db.cursor = self.db.connection.cursor()
        self.db.create_table()

    def tearDown(self):
        """Eliminar la base de datos de prueba después de cada prueba."""
        self.db.close()
        os.remove(self.test_db)

    def test_add_user(self):
        """Probar la adición de un nuevo usuario."""
        result = self.db.add_user('testuser', 'password123')
        self.assertTrue(result)

        # Intentar agregar el mismo usuario nuevamente
        result = self.db.add_user('testuser', 'password123')
        self.assertFalse(result)

    def test_verify_user(self):
        """Probar la verificación de un usuario existente."""
        self.db.add_user('testuser', 'password123')
        result = self.db.verify_user('testuser', 'password123')
        self.assertTrue(result)

        result = self.db.verify_user('testuser', 'wrongpassword')
        self.assertFalse(result)

    def test_hash_password(self):
        """Probar el hashing de contraseñas."""
        hashed_password = self.db.hash_password('password123')
        self.assertNotEqual(hashed_password, 'password123')
        self.assertEqual(len(hashed_password), 64)  # sha256 produce un hash de 64 caracteres

    def test_verify_password_security(self):
        """Probar la verificación de seguridad de la contraseña."""
        app = LoginApp()  # Crear una instancia de LoginApp
        app.db = self.db  # Asignar la base de datos a la instancia de LoginApp
        self.db.add_user('testuser', 'password123')
        
        # Simular la verificación de una contraseña común
        common_password = '123456'
        result = app.is_password_secure(common_password)  # Llamar al método desde LoginApp
        self.assertFalse(result)  # Debería ser vulnerable

        # Verificar una contraseña segura
        secure_password = 'S3cureP@ssw0rd!'
        result = app.is_password_secure(secure_password)  # Llamar al método desde LoginApp
        self.assertTrue(result)  # Debería ser segura

if __name__ == '__main__':
    unittest.main()
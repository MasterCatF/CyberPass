#pip install python-Levenshtein
from kivy.lang import Builder
from kivymd.app import MDApp
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDFlatButton, MDRaisedButton
from kivy.core.window import Window
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition  # Añadido SlideTransition
from kivy.utils import get_color_from_hex
from kivy.core.clipboard import Clipboard
from kivymd.toast import toast
import re
from kivy.clock import Clock
import random
import string
import sqlite3
from hashlib import sha256
import Levenshtein
import time  #NUEVO
import threading #NUEVO

Window.size = (300, 500)

KV = '''
#:import SlideTransition kivy.uix.screenmanager.SlideTransition
#:import utils kivy.utils

ScreenManager:
    transition: SlideTransition()
    LoginScreen:
    RegisterScreen:
    WelcomeScreen:
    VerifyPasswordScreen:
    GeneratePasswordScreen:

<CyberButton@MDRaisedButton>:
    md_bg_color: utils.get_color_from_hex("#00BCD4")
    text_color: 1, 1, 1, 1
    elevation: 5

<CyberScreen@Screen>:
    canvas.before:
        Color:
            rgba: utils.get_color_from_hex("#0D1117")
        Rectangle:
            pos: self.pos
            size: self.size
        Color:
            rgba: utils.get_color_from_hex("#1D2733")
        Line:
            points: [self.x, self.y, self.right, self.top]
            width: 2
        Line:
            points: [self.x, self.top, self.right, self.y]
            width: 2

<LoginScreen>:
    name: 'login'
    CyberScreen:
        MDCard:
            size_hint: None, None
            size: 280, 400
            pos_hint: {"center_x": 0.5, "center_y": 0.5}
            elevation: 10
            padding: 25
            spacing: 25
            md_bg_color: utils.get_color_from_hex("#1F2937")
            orientation: 'vertical'

            MDIcon:
                icon: 'shield-lock'
                font_size: 80
                halign: 'center'
                theme_text_color: "Custom"
                text_color: utils.get_color_from_hex("#00BCD4")

            MDTextField:
                id: user
                icon_right: "account"
                hint_text: "Username"
                foreground_color: 1, 1, 1, 1
                size_hint_x: None
                width: 220
                font_size: 18
                pos_hint: {"center_x": 0.5}

            MDTextField:
                id: password
                icon_right: "eye-off"
                hint_text: "Password"
                foreground_color: 1, 1, 1, 1
                size_hint_x: None
                width: 220
                font_size: 18
                pos_hint: {"center_x": 0.5}
                password: True

            CyberButton:
                text: "ENTRAR"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_release: app.login()

            CyberButton:
                text: "REGISTRARSE"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_release: app.root.current = 'register'

<RegisterScreen>:
    name: 'register'
    CyberScreen:
        MDCard:
            size_hint: None, None
            size: 280, 400
            pos_hint: {"center_x": 0.5, "center_y": 0.5}
            elevation: 10
            padding: 25
            spacing: 25
            md_bg_color: utils.get_color_from_hex("#1F2937")
            orientation: 'vertical'

            MDIcon:
                icon: 'account-plus'
                font_size: 80
                halign: 'center'
                theme_text_color: "Custom"
                text_color: utils.get_color_from_hex("#00BCD4")

            MDTextField:
                id: new_username
                icon_right: "account-plus"
                hint_text: "Usuario"
                foreground_color: 1, 1, 1, 1
                size_hint_x: None
                width: 220
                font_size: 18
                pos_hint: {"center_x": 0.5}

            MDTextField:
                id: new_password
                icon_right: "key-variant"
                hint_text: "Contraseña"
                foreground_color: 1, 1, 1, 1
                size_hint_x: None
                width: 220
                font_size: 18
                pos_hint: {"center_x": 0.5}
                password: True

            CyberButton:
                text: "REGISTRARSE"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_release: app.register_user()

            CyberButton:
                text: "VOLVER"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_release: app.root.current = 'login'

<WelcomeScreen>:
    name: 'welcome'
    CyberScreen:
        MDBoxLayout:
            orientation: 'vertical'
            spacing: 20
            padding: 20
            
            MDLabel:
                id: welcome_label
                text: "!Bienvenido!"
                halign: 'center'
                font_style: 'H4'
                theme_text_color: "Custom"
                text_color: utils.get_color_from_hex("#00BCD4")

            CyberButton:
                text: "Verificar Contraseña"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_release: app.switch_to_verify_password()

            CyberButton:
                text: "Generar Contraseña"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_release: app.switch_to_generate_password()

            CyberButton:
                text: "SALIR"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_release: app.root.current = 'login'

<VerifyPasswordScreen>:
    name: 'verify_password'
    CyberScreen:
        MDCard:
            size_hint: None, None
            size: 280, 400
            pos_hint: {"center_x": 0.5, "center_y": 0.5}
            elevation: 10
            padding: 25
            spacing: 25
            md_bg_color: utils.get_color_from_hex("#1F2937")
            orientation: 'vertical'

            MDIcon:
                icon: 'security'
                font_size: 80
                halign: 'center'
                theme_text_color: "Custom"
                text_color: utils.get_color_from_hex("#00BCD4")

            MDTextField:
                id: new_password
                icon_right: "key-variant"
                hint_text: "Ingrese la contraseña"
                foreground_color: 1, 1, 1, 1
                size_hint_x: None
                width: 220
                font_size: 18
                pos_hint: {"center_x": 0.5}
                password: True

            CyberButton:
                text: "Verificar Seguridad"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_release: app.verify_password()

            CyberButton:
                text: "volver"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_press: app.root.current = 'welcome'

<GeneratePasswordScreen>:
    name: 'generate_password'
    CyberScreen:
        MDCard:
            size_hint: None, None
            size: 280, 400
            pos_hint: {"center_x": 0.5, "center_y": 0.5}
            elevation: 10
            padding: 25
            spacing: 25
            md_bg_color: utils.get_color_from_hex("#1F2937")
            orientation: 'vertical'

            MDIcon:
                icon: 'key-plus'
                font_size: 80
                halign: 'center'
                theme_text_color: "Custom"
                text_color: utils.get_color_from_hex("#00BCD4")

            MDLabel:
                text: "Generar Contraseña"
                halign: 'center'
                font_style: 'H5'
                theme_text_color: "Custom"
                text_color: utils.get_color_from_hex("#FFFFFF")

            MDCard:
                size_hint: None, None
                size: 240, 60
                pos_hint: {"center_x": 0.5}
                md_bg_color: utils.get_color_from_hex("#2D3748")
                padding: 10

                MDLabel:
                    id: generated_password
                    text: "La Contraseña Aparece Aqui"
                    halign: 'center'
                    theme_text_color: "Custom"
                    text_color: utils.get_color_from_hex("#00BCD4")

            CyberButton:
                text: "Generar"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_release: app.generate_random_password()

            CyberButton:
                text: "Copiar"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_release: app.copy_to_clipboard()

            CyberButton:
                text: "Volver"
                font_size: 15
                pos_hint: {"center_x": 0.5}
                on_release: app.root.current = 'welcome'
'''

class Database:
    def __init__(self):
        self.connection = sqlite3.connect('users.db')
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        ''')
        self.connection.commit()

    def hash_password(self, password):
        return sha256(password.encode()).hexdigest()

    def add_user(self, username, password):
        try:
            hashed_password = self.hash_password(password)
            self.cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                              (username, hashed_password))
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_user(self, username, password):
        hashed_password = self.hash_password(password)
        self.cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                          (username, hashed_password))
        return self.cursor.fetchone() is not None

    def close(self):
        self.connection.close()

class LoginScreen(Screen):
    pass

class RegisterScreen(Screen):
    pass

class WelcomeScreen(Screen):
    pass

class VerifyPasswordScreen(Screen):
    pass

class GeneratePasswordScreen(Screen):
    pass

class LoginApp(MDApp):
    dialog = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.db = Database()

    def build(self):
        self.theme_cls.theme_style = 'Dark'
        self.theme_cls.primary_palette = 'Cyan'
        self.theme_cls.accent_palette = 'Teal'
        return Builder.load_string(KV)

    def show_dialog(self, title, text):
        if not self.dialog:
            self.dialog = MDDialog(
                title=title,
                text=text,
                buttons=[
                    MDFlatButton(
                        text="OK",
                        theme_text_color="Custom",
                        text_color=self.theme_cls.primary_color,
                        on_release=lambda x: self.dialog.dismiss()
                    )
                ]
            )
        self.dialog.text = text
        self.dialog.title = title
        self.dialog.open()

    def show_result_dialog(self, title, text):
        result_dialog = MDDialog(
            title=title,
            text=text,
            size_hint=(0.8, None),
            height=200,
            buttons=[
                MDFlatButton(
                    text="OK",
                    on_release=lambda x: result_dialog.dismiss()  # Cerrar solo al hacer clic
                )
            ]
        )
        result_dialog.open()

    def copy_to_clipboard(self):
        password = self.root.get_screen('generate_password').ids.generated_password.text
        if password != "La contraseña aparecera aqui":
            Clipboard.copy(password)
            toast("Contraseña copiada al portapapeles!")

    def login(self):
        username = self.root.get_screen('login').ids.user.text
        password = self.root.get_screen('login').ids.password.text

        if self.db.verify_user(username, password):
            self.root.get_screen('welcome').ids.welcome_label.text = f"!Bienvenido {username}!"
            self.root.current = 'welcome'
            toast(f"Bienvenido, {username}!")
        else:
            self.show_dialog("Error", "Invalido Usuario o Contraseña")

    def register_user(self):
        username = self.root.get_screen('register').ids.new_username.text
        password = self.root.get_screen('register').ids.new_password.text

        if not username or not password:
            self.show_dialog("Error", "Por favor llena todos los campos")
            return

        if self.db.add_user(username, password):
            self.show_dialog("Exito", "Usuario Registrado Satisfactoriamente!")
            self.root.current = 'login'
        else:
            self.show_dialog("Error", "Usuario ya existe")

    def generate_random_password(self):
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = '@$!%*?&#'
        
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        length = random.randint(12, 16)
        all_characters = lowercase + uppercase + digits + special
        for _ in range(length - 4):
            password.append(random.choice(all_characters))
        
        random.shuffle(password)
        final_password = ''.join(password)
        
        screen = self.root.get_screen('generate_password')
        screen.ids.generated_password.text = final_password
        toast("Nueva Contraseña Generada!")

    def verify_password(self):
        password = self.root.get_screen('verify_password').ids.new_password.text

        if not self.is_password_secure(password):
            self.show_dialog(
                "Error de Seguridad",
                "La contraseña es fácilmente vulnerable ya que está en una base de datos pública"
            )
            return

        if self.is_password_secure2(password):
            # Mostrar un diálogo que se mantenga abierto
            self.dialog = MDDialog(
                title="Esperar",
                text="Haciendo ataque de Fuerza Bruta...",
                size_hint=(0.8, None),
                height=200
            )
            self.dialog.open()
        
            # Iniciar un hilo para verificar la contraseña
            thread = threading.Thread(target=self.password_in_thread, args=(password,))
            thread.start()
        else:
            self.show_dialog(
                "Requerimientos de Seguridad",
                "La contraseña debería tener:\n\n" +
                "• Mínimo 8 caracteres\n" +
                "• Una letra mayúscula\n" +
                "• Una letra minúscula\n" +
                "• Un número\n" +
                "• Un carácter Especial"
            )

    def is_password_secure(self, password):             #AGREGADO
        with open('Comunes.txt', 'r') as file:
            self.common_passwords = set(line.strip() for line in file)
        

        if password in self.common_passwords:
            return False
        
        # Verificar similitudes con contraseñas comunes
        threshold = 3  # Número máximo de ediciones permitidas
        for common_password in self.common_passwords:
            if Levenshtein.distance(password, common_password) <= threshold:
                return False
        
        return True
    
    def is_password_secure2(self, password):
        if len(password) < 8:
            return False
        if not re.search("[a-z]", password):
            return False
        if not re.search("[A-Z]", password):
            return False
        if not re.search("[0-9]", password):
            return False
        if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
            return False
        return True

    def is_password_secure3(self, password):
        hashed_password = self.db.hash_password(password)
        start_time = time.time()
        
        with open('Ataque.txt', 'r', encoding='utf-8') as file :
            for line in file:
                common_password = line.strip()
                if self.db.hash_password(common_password) == hashed_password:
                    elapsed_time = time.time() - start_time
                    if elapsed_time < 60:  # 1 minuto en segundos
                        return elapsed_time  # Retorna el tiempo en segundos
                    else:
                        break  # Si pasa de 1 minuto, salimos del bucle
        
        return None 

    def password_in_thread(self, password):
        attack_time = self.is_password_secure3(password)

        # Cerrar el diálogo de "Haciendo ataque de Fuerza Bruta"
        if self.dialog:
            self.dialog.dismiss()

        # Usar Clock.schedule_once para abrir el diálogo en el hilo principal
        if attack_time is not None:
            Clock.schedule_once(lambda dt: self.show_result_dialog("Vulnerabilidad Detectada", f"La contraseña fue vulnerada en {attack_time:.2f} segundos.Use Otra"))
        else:
            Clock.schedule_once(lambda dt: self.show_result_dialog("Seguridad", "La contraseña no fue vulnerada rápidamente y cumple todos los estandares de seguridad"))

    def switch_to_verify_password(self):
        self.root.current = 'verify_password'
        toast("Digite una contraseña para verificarla")

    def switch_to_generate_password(self):
        self.root.current = 'generate_password'
        toast("Generar contraseña segura")

    def on_stop(self):
        """Se llama cuando la aplicación se cierra"""
        self.db.close()

if __name__ == '__main__':
    LoginApp().run()